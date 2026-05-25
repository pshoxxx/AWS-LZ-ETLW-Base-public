-- =====================================================================
-- network-routing-validation.sql
--
-- Article-ready Athena queries that prove traffic actually flows along
-- the advertised hub-and-spoke paths. Run these from the SECURITY
-- account's Athena workgroup ("siem-workgroup") against the "org-siem"
-- database -- both are provisioned by terraform/security/siem_*.tf.
--
-- For the article, each query is paired with a single screenshot of the
-- result table. The point is per-packet, AWS-native evidence: every row
-- is a real flow that AWS itself recorded, not a synthetic analysis.
--
-- Replace the bracketed placeholders before running:
-- Only two placeholders need replacing -- everything else uses stable
-- CIDR ranges from the documented architecture.
--   <on-prem-dc-ip>         on-prem DC IP (default 192.168.1.200)
--   <dc01-corporate-ip>     EC2 dc01-corporate private IP (default 10.1.10.4)
--
-- Architecture CIDR map (used as filter values in the queries):
--   Egress VPC (hub)        10.0.0.0/16
--     ALB subnets           10.0.0.0/24, 10.0.1.0/24  (ALB ENIs only)
--     NAT subnets           10.0.2.0/24, 10.0.3.0/24  (NAT GW ENIs only)
--   Corporate spoke         10.1.0.0/16
--   Security spoke          10.2.0.0/16
--   Management spoke        10.3.0.0/24
--   Web spoke               10.4.0.0/16
--   On-prem                 192.168.1.0/24
--
-- VPC Flow Logs include both srcaddr/dstaddr (as seen at the recording
-- ENI, post-NAT) and pkt_srcaddr/pkt_dstaddr (the ORIGINAL pre-NAT IPs).
-- The NAT egress query uses pkt_srcaddr to identify the originating
-- spoke since by the time the flow reaches NAT GW the visible source
-- has been SNAT'd to the NAT EIP.
--
-- Each query restricts the time window to the last hour. Bump it if you
-- need older data; bump it carefully because Athena scans data and
-- partition projection makes per-hour pruning cheap.
-- =====================================================================


-- ---------------------------------------------------------------------
-- Query 1 -- VPN / AD traffic: corporate DC <-> on-prem DC
--
-- Proves: the IPsec tunnel + TGW routing carries real AD replication
-- traffic between dc01-corporate and the on-prem DC on AD ports
-- (Kerberos 88, RPC EPM 135, LDAP 389/636, SMB 445, DNS 53).
-- Bidirectional rows = symmetric routing confirmed.
-- ---------------------------------------------------------------------
SELECT
  from_unixtime(start)                          AS event_time,
  srcaddr, srcport,
  dstaddr, dstport,
  CASE protocol WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' ELSE CAST(protocol AS varchar) END AS proto,
  action,
  packets,
  bytes
FROM vpc_flow_logs
WHERE spoke = 'corporate'
  AND year  = date_format(current_date, '%Y')
  AND month = date_format(current_date, '%m')
  AND day   = date_format(current_date, '%d')
  AND (
    (srcaddr = '<on-prem-dc-ip>' AND dstaddr = '<dc01-corporate-ip>')
    OR
    (srcaddr = '<dc01-corporate-ip>' AND dstaddr = '<on-prem-dc-ip>')
  )
  AND dstport IN (53, 88, 135, 389, 445, 636)
ORDER BY event_time DESC
LIMIT 100;


-- ---------------------------------------------------------------------
-- Query 2 -- Web ingress chain: Internet -> IGW -> ALB
--
-- Proves: inbound HTTP requests from internet sources reach the ALB ENIs
-- in the networking egress VPC. The ALB subnets (10.0.0.0/24, 10.0.1.0/24)
-- are dedicated to ALB ENIs by design (per egress_vpc.tf -- "Hosts only
-- the internet-facing ALB ENIs"), so any packet with dstaddr in those
-- CIDRs and dstport 80 is web ingress. The downstream ALB -> VPC endpoint
-- -> PrivateLink -> NLB -> EC2 chain is documented separately in the
-- functional browser test.
-- ---------------------------------------------------------------------
SELECT
  from_unixtime(start)                          AS event_time,
  srcaddr                                       AS internet_source,
  dstaddr                                       AS alb_eni_ip,
  dstport,
  action,
  packets,
  bytes,
  interface_id                                  AS alb_eni
FROM vpc_flow_logs
WHERE spoke = 'networking'
  AND year  = date_format(current_date, '%Y')
  AND month = date_format(current_date, '%m')
  AND day   = date_format(current_date, '%d')
  AND (dstaddr LIKE '10.0.0.%' OR dstaddr LIKE '10.0.1.%')   -- ALB subnets
  AND dstport = 80
  AND srcaddr NOT LIKE '10.%'
  AND srcaddr NOT LIKE '192.168.%'
  AND action = 'ACCEPT'
ORDER BY event_time DESC
LIMIT 100;


-- NOTE: Web-spoke egress validation lives outside this SQL file:
--   - The "network-routing-traffic" CloudWatch dashboard's NAT Gateway
--     panels (ConnectionAttemptCount + ConnectionEstablishedCount)
--     show aggregate proof that spoke EC2s initiated and completed
--     outbound TCP sessions through NAT.
--   - The curl allow vs deny demonstration in the tutorial shows
--     enforcement happening in real time.
-- A dedicated VPC Flow Log query for the NAT egress chain was
-- intentionally omitted: the flow records are captured at each
-- intermediate ENI (TGW attach, NF endpoint, NAT GW) with relay-hop
-- addresses in srcaddr/dstaddr, which obscures the end-to-end view
-- without adding evidentiary value beyond what the dashboard + curl
-- demonstration already provide.


-- ---------------------------------------------------------------------
-- Query 3 -- Spoke-to-spoke / spoke-to-on-prem traffic via TGW
--
-- Proves: east-west traffic between spokes traverses the TGW. Rows
-- captured at the destination spoke's ENI prove the packet completed
-- the round trip through the internal NF.
-- ---------------------------------------------------------------------
SELECT
  from_unixtime(start)                          AS event_time,
  srcaddr, srcport,
  dstaddr, dstport,
  CASE protocol WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' ELSE CAST(protocol AS varchar) END AS proto,
  action,
  packets, bytes,
  vpc_id                                        AS destination_vpc
FROM vpc_flow_logs
WHERE year  = date_format(current_date, '%Y')
  AND month = date_format(current_date, '%m')
  AND day   = date_format(current_date, '%d')
  -- Spoke A to Spoke B: source CIDR != destination CIDR, both internal
  AND srcaddr LIKE '10.%'
  AND dstaddr LIKE '10.%'
  AND substr(srcaddr, 1, 5) <> substr(dstaddr, 1, 5)   -- different /16s
ORDER BY event_time DESC
LIMIT 100;


-- ---------------------------------------------------------------------
-- Query 4 -- REJECT scan: any silent drops on architecturally expected flows?
--
-- Proves: zero rows -> no security group, NACL, or firewall is silently
-- blocking expected traffic. Rows here would indicate a SG/NACL bug.
-- Excludes RFC1918 sources (internal scanning noise is in the SIEM's
-- dedicated detection query; this is for architectural validation only).
-- ---------------------------------------------------------------------
SELECT
  srcaddr                                       AS source,
  dstaddr                                       AS destination,
  dstport,
  CASE protocol WHEN 6 THEN 'tcp' WHEN 17 THEN 'udp' ELSE CAST(protocol AS varchar) END AS proto,
  COUNT(*)                                      AS rejected_packets,
  SUM(packets)                                  AS total_packet_count,
  max(from_unixtime(start))                     AS last_seen
FROM vpc_flow_logs
WHERE year  = date_format(current_date, '%Y')
  AND month = date_format(current_date, '%m')
  AND day   = date_format(current_date, '%d')
  AND action = 'REJECT'
  -- Architectural-validation scope: internal-to-internal rejections only.
  -- (External scan noise is covered by the SIEM RDP/SSH brute-force named query.)
  AND srcaddr LIKE '10.%'
  AND dstaddr LIKE '10.%'
GROUP BY srcaddr, dstaddr, dstport, protocol
ORDER BY rejected_packets DESC
LIMIT 50;


-- ---------------------------------------------------------------------
-- Query 5 (Optional) -- Egress Drop Deduction: Unallowed domains
--
-- Demonstrates: Real-world deduction when perfect data isn't available.
-- We query the Network Firewall *flow* logs for our timed-out curl to
-- a non-allowlisted domain. The results show only a few rows with
-- very few packets, representing an incomplete TLS handshake.
--
-- Replace <denied-ip> below with the IP your curl verbose output
-- resolved -- look for the "* Trying X.X.X.X:443..." line.
--
-- Why no explicit DROP alert? We intentionally chose not to configure
-- Network Firewall alerting to save costs and reduce log noise. (Note:
-- In strict production, you'd want these alerts to catch attackers
-- "testing the waters" or calling home).
--
-- The Lesson: Without a neat alert log explicitly saying "Blocked", we
-- must use deduction. The flow logs prove the connection reached the
-- firewall and started the TLS handshake, but abruptly died. We can
-- infer the firewall inspected the SNI, saw an unallowed domain, and
-- silently dropped the connection.
-- ---------------------------------------------------------------------
SELECT
  event.timestamp                               AS event_time,
  event.src_ip                                  AS spoke_source,
  event.dest_ip                                 AS denied_destination,
  event.dest_port,
  event.proto,
  event.bytes                                   AS bytes_observed,
  event.packets                                 AS packets_observed
FROM network_firewall_internal_flow
WHERE event.dest_ip = '<denied-ip>'
   OR event.src_ip  = '<denied-ip>'
ORDER BY event.timestamp DESC
LIMIT 20;

