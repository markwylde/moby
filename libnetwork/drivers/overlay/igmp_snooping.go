//go:build linux

package overlay

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/containerd/log"
	"github.com/docker/docker/libnetwork/osl"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv4"
)

const (
	igmpTypeQuery       = 0x11
	igmpTypeReportV1    = 0x12
	igmpTypeReportV2    = 0x16
	igmpTypeReportV3    = 0x22
	igmpTypeLeave       = 0x17
	igmpQueryInterval   = 125 * time.Second
	igmpResponseTime    = 10 * time.Second
)

// igmpSnooper manages IGMP snooping for a network
type igmpSnooper struct {
	n        *network
	d        *driver
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// startIGMPSnooping starts IGMP snooping on the bridge interface
func (n *network) startIGMPSnooping(sbox *osl.Namespace, brName string) error {
	snooper := &igmpSnooper{
		n:      n,
		d:      n.driver,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	// Start the snooping goroutine
	go snooper.run(sbox, brName)

	// Store the snooper for cleanup
	n.igmpSnooper = snooper

	log.G(context.TODO()).Infof("Started IGMP snooping for network %s on bridge %s", n.id, brName)
	return nil
}

// stopIGMPSnooping stops IGMP snooping
func (n *network) stopIGMPSnooping() {
	if n.igmpSnooper != nil {
		close(n.igmpSnooper.stopCh)
		<-n.igmpSnooper.doneCh
		n.igmpSnooper = nil
		log.G(context.TODO()).Infof("Stopped IGMP snooping for network %s", n.id)
	}
}

// run is the main IGMP snooping loop
func (s *igmpSnooper) run(sbox *osl.Namespace, brName string) {
	defer close(s.doneCh)

	var conn *ipv4.RawConn
	err := sbox.InvokeFunc(func() error {
		// Create raw socket for IGMP packets
		c, err := net.ListenPacket("ip4:igmp", "0.0.0.0")
		if err != nil {
			return fmt.Errorf("failed to create IGMP socket: %v", err)
		}

		rc, err := ipv4.NewRawConn(c)
		if err != nil {
			c.Close()
			return fmt.Errorf("failed to create raw conn: %v", err)
		}

		conn = rc
		return nil
	})

	if err != nil {
		log.G(context.TODO()).Errorf("Failed to start IGMP snooping: %v", err)
		return
	}
	defer conn.Close()

	// Start IGMP query timer
	queryTicker := time.NewTicker(igmpQueryInterval)
	defer queryTicker.Stop()

	// Packet buffer
	buf := make([]byte, 1500)

	for {
		select {
		case <-s.stopCh:
			return
		case <-queryTicker.C:
			// Send IGMP general query
			s.sendIGMPQuery(sbox, brName)
		default:
			// Set read timeout
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			// Read IGMP packet
			header, payload, _, err := conn.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.G(context.TODO()).Debugf("Failed to read IGMP packet: %v", err)
				continue
			}

			// Process IGMP packet
			s.processIGMPPacket(header, payload)
		}
	}
}

// processIGMPPacket processes an IGMP packet
func (s *igmpSnooper) processIGMPPacket(header *ipv4.Header, payload []byte) {
	if len(payload) < 8 {
		return // Too short for IGMP
	}

	igmpType := payload[0]
	sourceIP := header.Src

	switch igmpType {
	case igmpTypeReportV1, igmpTypeReportV2:
		// IGMPv1/v2 membership report
		groupIP := net.IP(payload[4:8])
		s.handleIGMPJoin(sourceIP, groupIP)

	case igmpTypeReportV3:
		// IGMPv3 membership report
		if len(payload) < 12 {
			return
		}
		numRecords := int(payload[6])<<8 | int(payload[7])
		offset := 8
		for i := 0; i < numRecords && offset+8 <= len(payload); i++ {
			recordType := payload[offset]
			groupIP := net.IP(payload[offset+4 : offset+8])
			
			switch recordType {
			case 1, 2, 3, 4: // Various join types
				s.handleIGMPJoin(sourceIP, groupIP)
			case 5, 6: // Leave types
				s.handleIGMPLeave(sourceIP, groupIP)
			}
			
			// Skip to next record
			auxDataLen := int(payload[offset+1])
			numSources := int(payload[offset+2])<<8 | int(payload[offset+3])
			offset += 8 + numSources*4 + auxDataLen*4
		}

	case igmpTypeLeave:
		// Leave group
		groupIP := net.IP(payload[4:8])
		s.handleIGMPLeave(sourceIP, groupIP)
	}
}

// handleIGMPJoin handles a container joining a multicast group
func (s *igmpSnooper) handleIGMPJoin(sourceIP, groupIP net.IP) {
	srcAddr, ok := netip.AddrFromSlice(sourceIP)
	if !ok {
		return
	}
	grpAddr, ok := netip.AddrFromSlice(groupIP)
	if !ok || !grpAddr.IsMulticast() {
		return
	}

	// Find the endpoint for this source IP
	ep := s.findEndpointByIP(srcAddr)
	if ep == nil {
		log.G(context.TODO()).Debugf("No endpoint found for source IP %s", sourceIP)
		return
	}

	log.G(context.TODO()).Infof("Container %s/%s joining multicast group %s", ep.id, sourceIP, groupIP)

	// Update peerdb with group membership
	if err := s.d.peerDbJoinMulticastGroup(s.n.id, ep.id, srcAddr, grpAddr); err != nil {
		log.G(context.TODO()).Warnf("Failed to update peerdb for group join: %v", err)
		return
	}

	// Update FDB entries for this group
	s.updateMulticastFDB(grpAddr)

	// Propagate group membership to other peers via gossip
	s.propagateGroupMembership(ep.id, srcAddr, grpAddr, true)
}

// handleIGMPLeave handles a container leaving a multicast group
func (s *igmpSnooper) handleIGMPLeave(sourceIP, groupIP net.IP) {
	srcAddr, ok := netip.AddrFromSlice(sourceIP)
	if !ok {
		return
	}
	grpAddr, ok := netip.AddrFromSlice(groupIP)
	if !ok || !grpAddr.IsMulticast() {
		return
	}

	// Find the endpoint for this source IP
	ep := s.findEndpointByIP(srcAddr)
	if ep == nil {
		return
	}

	log.G(context.TODO()).Infof("Container %s/%s leaving multicast group %s", ep.id, sourceIP, groupIP)

	// Update peerdb with group membership
	if err := s.d.peerDbLeaveMulticastGroup(s.n.id, ep.id, srcAddr, grpAddr); err != nil {
		log.G(context.TODO()).Warnf("Failed to update peerdb for group leave: %v", err)
		return
	}

	// Update FDB entries for this group
	s.updateMulticastFDB(grpAddr)

	// Propagate group membership to other peers via gossip
	s.propagateGroupMembership(ep.id, srcAddr, grpAddr, false)
}

// updateMulticastFDB updates FDB entries based on current group membership
func (s *igmpSnooper) updateMulticastFDB(groupIP netip.Addr) {
	// Get all VTEPs that have members for this group
	vteps := s.d.peerDbGetMulticastMembers(s.n.id, groupIP)
	
	groupMac := multicastIPToMAC(groupIP)
	if groupMac == nil {
		return
	}

	log.G(context.TODO()).Infof("Updating FDB for group %s: %d VTEPs with members", groupIP, len(vteps))

	// Update FDB entries for each subnet
	for _, subnet := range s.n.subnets {
		// Remove all existing FDB entries for this group
		s.clearMulticastFDBForGroup(subnet, groupMac)

		// Add FDB entries only for VTEPs with group members
		for _, vtep := range vteps {
			if err := s.n.addMulticastFDBEntry(vtep, groupMac, subnet.vni); err != nil {
				log.G(context.TODO()).Warnf("Failed to add FDB entry for group %s to VTEP %s: %v", 
					groupIP, vtep, err)
			}
		}
	}
}

// clearMulticastFDBForGroup removes all FDB entries for a multicast group
func (s *igmpSnooper) clearMulticastFDBForGroup(subnet *subnet, groupMac net.HardwareAddr) {
	vxlan, err := netlink.LinkByName(subnet.vxlanName)
	if err != nil {
		return
	}

	// List all FDB entries
	neighs, err := netlink.NeighList(vxlan.Attrs().Index, netlink.FAMILY_ALL)
	if err != nil {
		return
	}

	// Remove entries matching the group MAC
	for _, neigh := range neighs {
		if neigh.HardwareAddr.String() == groupMac.String() {
			netlink.NeighDel(&neigh)
		}
	}
}

// findEndpointByIP finds an endpoint by its IP address
func (s *igmpSnooper) findEndpointByIP(ip netip.Addr) *endpoint {
	s.n.Lock()
	defer s.n.Unlock()

	for _, ep := range s.n.endpoints {
		if ep.addr != nil && ep.addr.Addr() == ip {
			return ep
		}
	}
	return nil
}

// sendIGMPQuery sends an IGMP general query
func (s *igmpSnooper) sendIGMPQuery(sbox *osl.Namespace, brName string) error {
	// Create IGMP general query packet
	query := make([]byte, 8)
	query[0] = igmpTypeQuery          // Type
	query[1] = 100                    // Max response time (10 seconds in 1/10 second units)
	// Checksum will be calculated later
	// Group address = 0.0.0.0 for general query

	// Calculate checksum
	checksum := igmpChecksum(query)
	query[2] = byte(checksum >> 8)
	query[3] = byte(checksum & 0xff)

	// Send query to all-hosts multicast group (224.0.0.1)
	allHosts := netip.MustParseAddr("224.0.0.1")
	
	err := sbox.InvokeFunc(func() error {
		// Create raw socket
		conn, err := net.Dial("ip4:igmp", allHosts.String())
		if err != nil {
			return fmt.Errorf("failed to create IGMP socket: %v", err)
		}
		defer conn.Close()

		// Send the query
		_, err = conn.Write(query)
		return err
	})

	if err != nil {
		log.G(context.TODO()).Debugf("Failed to send IGMP query: %v", err)
		return err
	}

	log.G(context.TODO()).Debugf("Sent IGMP general query on network %s", s.n.id)
	
	// Also trigger generation of membership reports based on peerdb state
	s.generateMembershipReports()
	
	return nil
}

// generateMembershipReports generates IGMP membership reports based on peerdb state
func (s *igmpSnooper) generateMembershipReports() {
	// Walk through all local peers and their group memberships
	s.d.peerDbNetworkWalk(s.n.id, func(peerIP netip.Addr, peerMAC net.HardwareAddr, pEntry *peerEntry) bool {
		if !pEntry.isLocal {
			return false
		}

		// For each multicast group this peer has joined, generate a report
		if pEntry.multicastGroups != nil {
			for groupIP := range pEntry.multicastGroups {
				s.sendMembershipReport(peerIP, groupIP)
			}
		}

		return false
	})
}

// sendMembershipReport sends an IGMP membership report for a specific group
func (s *igmpSnooper) sendMembershipReport(sourceIP, groupIP netip.Addr) error {
	// Create IGMPv2 membership report
	report := make([]byte, 8)
	report[0] = igmpTypeReportV2     // Type
	report[1] = 0                    // Unused
	// Checksum will be calculated later
	copy(report[4:8], groupIP.AsSlice()) // Group address

	// Calculate checksum
	checksum := igmpChecksum(report)
	report[2] = byte(checksum >> 8)
	report[3] = byte(checksum & 0xff)

	// Send report (would normally be sent from sourceIP to groupIP)
	log.G(context.TODO()).Debugf("Generated IGMP membership report for %s joining group %s", sourceIP, groupIP)
	
	// In a real implementation, this would inject the packet onto the bridge
	// For now, we're using it to maintain consistency between peerdb and IGMP state
	
	return nil
}

// igmpChecksum calculates the IGMP checksum
func igmpChecksum(data []byte) uint16 {
	var sum uint32

	// Add each 16-bit word
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 + uint32(data[i+1])
	}

	// Add left-over byte, if any
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Add carry bits
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	// One's complement
	return uint16(^sum)
}

// propagateGroupMembership propagates group membership changes to other peers
func (s *igmpSnooper) propagateGroupMembership(eid string, peerIP, groupIP netip.Addr, join bool) {
	// Use peerAdd/peerDelete with multicast group IP to propagate membership
	// The multicast IP in the prefix indicates this is a group membership update
	groupPrefix := netip.PrefixFrom(groupIP, 32)
	
	// Create a synthetic MAC for the multicast group
	groupMAC := multicastIPToMAC(groupIP)
	
	if join {
		// Add multicast "peer" entry - this will be propagated via gossip
		s.d.peerAdd(s.n.id, eid, groupPrefix, groupMAC, s.d.advertiseAddress, false)
		log.G(context.TODO()).Infof("Propagated multicast join: endpoint %s joined group %s", eid, groupIP)
	} else {
		// Delete multicast "peer" entry
		s.d.peerDelete(s.n.id, eid, groupPrefix, groupMAC, s.d.advertiseAddress, false)
		log.G(context.TODO()).Infof("Propagated multicast leave: endpoint %s left group %s", eid, groupIP)
	}
}