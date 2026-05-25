-- ============================================================================
-- Network Exposure - Query Items and Cleanup (Oracle Autonomous Database)
--
-- Focus:
--   1) Identify orphan/unused security controls (Security Lists and NSGs)
--   2) Inspect exposure for a specific target VNIC or IP
--
-- Suggested usage:
--   1) Connect with a user that owns the tables, OR
--   2) Run: ALTER SESSION SET CURRENT_SCHEMA = <schema_name>;
-- ============================================================================


-- ============================================================================
-- Security Lists Not In Use
-- Returns security lists that are not attached to any subnet.
-- Adds CIS_insecure_case (ALL, 22, 3389) when matching risky inbound rules exist.
-- ============================================================================
WITH used_securitylists AS (
  SELECT DISTINCT
    sl_ids.securitylist_id
  FROM SUBNETS s
  CROSS APPLY json_table(
    s.data,
    '$."additional_details"."securityListIds"[*]'
    COLUMNS (
      securitylist_id VARCHAR2(200) PATH '$'
    )
  ) sl_ids
),
sl_details AS (
  SELECT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id,
    json_value(sl.data, '$."display_name"' RETURNING VARCHAR2(200)) AS securitylist_name,
    json_value(sl.data, '$."compartment_id"' RETURNING VARCHAR2(200)) AS compartment_id,
    json_value(sl.data, '$."lifecycle_state"' RETURNING VARCHAR2(50)) AS lifecycle_state,
    json_value(sl.data, '$."time_created"' RETURNING VARCHAR2(64)) AS time_created,
    json_value(sl.data, '$."additional_details"."vcnId"' RETURNING VARCHAR2(200)) AS vcn_id
  FROM SECURITYLISTS sl
),
sl_insecure_cases AS (
  SELECT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id,
    CASE
      WHEN r.source = '0.0.0.0/0'
       AND (r.protocol = 'all' OR (r.protocol = '6' AND r.tcp_options_json IS NULL))
        THEN 'ALL'
      WHEN r.source = '0.0.0.0/0'
       AND r.protocol = '6'
       AND r.tcp_port_min IS NOT NULL
       AND r.tcp_port_max IS NOT NULL
       AND 22 BETWEEN r.tcp_port_min AND r.tcp_port_max
        THEN '22'
      WHEN r.source = '0.0.0.0/0'
       AND r.protocol = '6'
       AND r.tcp_port_min IS NOT NULL
       AND r.tcp_port_max IS NOT NULL
       AND 3389 BETWEEN r.tcp_port_min AND r.tcp_port_max
        THEN '3389'
    END AS cis_insecure_case
  FROM SECURITYLISTS sl
  CROSS APPLY json_table(
    sl.data,
    '$."additional_details"."ingressSecurityRules"[*]'
    COLUMNS (
      source VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_options_json CLOB FORMAT JSON PATH '$."tcpOptions"',
      tcp_port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      tcp_port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"'
    )
  ) r
),
sl_insecure_agg AS (
  SELECT
    securitylist_id,
    LISTAGG(cis_insecure_case, ', ') WITHIN GROUP (
      ORDER BY CASE cis_insecure_case WHEN 'ALL' THEN 1 WHEN '22' THEN 2 WHEN '3389' THEN 3 ELSE 9 END
    ) AS cis_insecure_case
  FROM (
    SELECT DISTINCT securitylist_id, cis_insecure_case
    FROM sl_insecure_cases
    WHERE cis_insecure_case IS NOT NULL
  ) x
  GROUP BY securitylist_id
)
SELECT
  d.securitylist_name,
  d.securitylist_id,
  d.vcn_id,
  d.compartment_id,
  d.lifecycle_state,
  d.time_created,
  COALESCE(a.cis_insecure_case, 'NONE') AS cis_insecure_case
FROM sl_details d
LEFT JOIN used_securitylists u
  ON u.securitylist_id = d.securitylist_id
LEFT JOIN sl_insecure_agg a
  ON a.securitylist_id = d.securitylist_id
WHERE u.securitylist_id IS NULL
ORDER BY d.securitylist_name, d.securitylist_id;


-- ============================================================================
-- NSGs Not In Use
-- Returns NSGs that are not attached to any VNIC.
-- Adds CIS_insecure_case (ALL, 22, 3389) when matching risky inbound rules exist.
-- ============================================================================
WITH used_nsgs AS (
  SELECT DISTINCT
    json_value(a.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id
  FROM NSGVNIC a
),
nsg_details AS (
  SELECT
    COALESCE(
      json_value(n.data, '$."identifier"' RETURNING VARCHAR2(200)),
      json_value(n.data, '$."id"' RETURNING VARCHAR2(200))
    ) AS nsg_id,
    json_value(n.data, '$."display_name"' RETURNING VARCHAR2(200)) AS nsg_name,
    json_value(n.data, '$."compartment_id"' RETURNING VARCHAR2(200)) AS compartment_id,
    json_value(n.data, '$."lifecycle_state"' RETURNING VARCHAR2(50)) AS lifecycle_state,
    json_value(n.data, '$."time_created"' RETURNING VARCHAR2(64)) AS time_created,
    json_value(n.data, '$."additional_details"."vcnId"' RETURNING VARCHAR2(200)) AS vcn_id
  FROM NSGDATA n
),
nsg_insecure_cases AS (
  SELECT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    CASE
      WHEN json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
       AND json_value(r.data, '$."source"' RETURNING VARCHAR2(64)) = '0.0.0.0/0'
       AND (
         json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = 'all'
         OR (
           json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
           AND json_query(r.data, '$."tcp_options"' RETURNING CLOB) IS NULL
         )
       ) THEN 'ALL'
      WHEN json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
       AND json_value(r.data, '$."source"' RETURNING VARCHAR2(64)) = '0.0.0.0/0'
       AND json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) IS NOT NULL
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) IS NOT NULL
       AND 22 BETWEEN
         json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
         AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
        THEN '22'
      WHEN json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
       AND json_value(r.data, '$."source"' RETURNING VARCHAR2(64)) = '0.0.0.0/0'
       AND json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) IS NOT NULL
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) IS NOT NULL
       AND 3389 BETWEEN
         json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
         AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
        THEN '3389'
    END AS cis_insecure_case
  FROM NSGRULES r
),
nsg_insecure_agg AS (
  SELECT
    nsg_id,
    LISTAGG(cis_insecure_case, ', ') WITHIN GROUP (
      ORDER BY CASE cis_insecure_case WHEN 'ALL' THEN 1 WHEN '22' THEN 2 WHEN '3389' THEN 3 ELSE 9 END
    ) AS cis_insecure_case
  FROM (
    SELECT DISTINCT nsg_id, cis_insecure_case
    FROM nsg_insecure_cases
    WHERE cis_insecure_case IS NOT NULL
  ) x
  GROUP BY nsg_id
)
SELECT
  d.nsg_name,
  d.nsg_id,
  d.vcn_id,
  d.compartment_id,
  d.lifecycle_state,
  d.time_created,
  COALESCE(a.cis_insecure_case, 'NONE') AS cis_insecure_case
FROM nsg_details d
LEFT JOIN used_nsgs u
  ON u.nsg_id = d.nsg_id
LEFT JOIN nsg_insecure_agg a
  ON a.nsg_id = d.nsg_id
WHERE u.nsg_id IS NULL
ORDER BY d.nsg_name, d.nsg_id;


-- ============================================================================
-- VNIC Exposure Lookup (By OCID)
-- Prompts for a VNIC OCID and returns all effective ingress rules from:
--   - Security Lists attached to the VNIC subnet
--   - NSGs attached to the VNIC
-- Includes VCN/Subnet context and source/destination service details per rule.
-- ============================================================================
WITH input_param AS (
  SELECT '&vnic_ocid' AS vnic_ocid FROM dual
),
vnic_target AS (
  SELECT
    json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) AS vnic_id,
    json_value(v.data, '$."display_name"' RETURNING VARCHAR2(200)) AS vnic_name,
    json_value(v.data, '$."additional_details"."subnetId"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(v.data, '$."additional_details"."privateIp"' RETURNING VARCHAR2(64)) AS private_ip,
    json_value(v.data, '$."additional_details"."publicIp"' RETURNING VARCHAR2(64)) AS public_ip
  FROM VNICS v
  JOIN input_param p
    ON json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) = p.vnic_ocid
),
subnet_details AS (
  SELECT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."vcnId"' RETURNING VARCHAR2(200)) AS vcn_id,
    REGEXP_SUBSTR(
      json_value(s.data, '$."additional_details"."subnetDomainName"' RETURNING VARCHAR2(500)),
      '\\.([^.]+)\\.oraclevcn\\.com$',
      1,
      1,
      NULL,
      1
    ) AS vcn_name
  FROM SUBNETS s
),
subnet_sl AS (
  SELECT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    sl_ids.securitylist_id
  FROM SUBNETS s
  CROSS APPLY json_table(
    s.data,
    '$."additional_details"."securityListIds"[*]'
    COLUMNS (
      securitylist_id VARCHAR2(200) PATH '$'
    )
  ) sl_ids
),
sl_rules AS (
  SELECT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id,
    json_value(sl.data, '$."display_name"' RETURNING VARCHAR2(200)) AS securitylist_name,
    r.rule_no,
    r.source,
    r.protocol,
    r.tcp_port_min,
    r.tcp_port_max,
    r.udp_port_min,
    r.udp_port_max
  FROM SECURITYLISTS sl
  CROSS APPLY json_table(
    sl.data,
    '$."additional_details"."ingressSecurityRules"[*]'
    COLUMNS (
      rule_no FOR ORDINALITY,
      source VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      tcp_port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"',
      udp_port_min NUMBER PATH '$."udpOptions"."destinationPortRange"."min"',
      udp_port_max NUMBER PATH '$."udpOptions"."destinationPortRange"."max"'
    )
  ) r
),
nsg_vnic_assoc AS (
  SELECT
    json_value(a.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(a.data, '$."vnic_id"' RETURNING VARCHAR2(200)) AS vnic_id
  FROM NSGVNIC a
),
nsg_data AS (
  SELECT
    COALESCE(
      json_value(n.data, '$."identifier"' RETURNING VARCHAR2(200)),
      json_value(n.data, '$."id"' RETURNING VARCHAR2(200))
    ) AS nsg_id,
    json_value(n.data, '$."display_name"' RETURNING VARCHAR2(200)) AS nsg_name
  FROM NSGDATA n
),
nsg_rules AS (
  SELECT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(r.data, '$."id"' RETURNING VARCHAR2(64)) AS rule_id,
    json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) AS direction,
    json_value(r.data, '$."source"' RETURNING VARCHAR2(64)) AS source,
    json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) AS protocol,
    json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) AS tcp_port_min,
    json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) AS tcp_port_max,
    json_value(r.data, '$."udp_options"."destination_port_range"."min"' RETURNING NUMBER) AS udp_port_min,
    json_value(r.data, '$."udp_options"."destination_port_range"."max"' RETURNING NUMBER) AS udp_port_max
  FROM NSGRULES r
)
SELECT
  vt.vnic_id,
  vt.vnic_name,
  vt.private_ip,
  vt.public_ip,
  sd.vcn_name,
  sd.vcn_id,
  sd.subnet_name,
  sd.subnet_id,
  'SECURITY_LIST' AS rule_source,
  slr.securitylist_name AS policy_name,
  slr.securitylist_id AS policy_id,
  TO_CHAR(slr.rule_no) AS rule_id,
  slr.source AS source_cidr,
  CASE
    WHEN slr.protocol = '6' THEN 'TCP'
    WHEN slr.protocol = '17' THEN 'UDP'
    WHEN slr.protocol = 'all' THEN 'ALL'
    ELSE slr.protocol
  END AS protocol,
  CASE
    WHEN slr.protocol = '17' THEN
      CASE
        WHEN slr.udp_port_min IS NULL OR slr.udp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN slr.udp_port_min = slr.udp_port_max THEN TO_CHAR(slr.udp_port_min)
        ELSE TO_CHAR(slr.udp_port_min) || '-' || TO_CHAR(slr.udp_port_max)
      END
    ELSE
      CASE
        WHEN slr.tcp_port_min IS NULL OR slr.tcp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN slr.tcp_port_min = slr.tcp_port_max THEN TO_CHAR(slr.tcp_port_min)
        ELSE TO_CHAR(slr.tcp_port_min) || '-' || TO_CHAR(slr.tcp_port_max)
      END
  END AS destination_service_port
FROM vnic_target vt
JOIN subnet_details sd
  ON sd.subnet_id = vt.subnet_id
JOIN subnet_sl ss
  ON ss.subnet_id = vt.subnet_id
JOIN sl_rules slr
  ON slr.securitylist_id = ss.securitylist_id
UNION ALL
SELECT
  vt.vnic_id,
  vt.vnic_name,
  vt.private_ip,
  vt.public_ip,
  sd.vcn_name,
  sd.vcn_id,
  sd.subnet_name,
  sd.subnet_id,
  'NSG' AS rule_source,
  nd.nsg_name AS policy_name,
  nr.nsg_id AS policy_id,
  nr.rule_id,
  nr.source AS source_cidr,
  CASE
    WHEN nr.protocol = '6' THEN 'TCP'
    WHEN nr.protocol = '17' THEN 'UDP'
    WHEN nr.protocol = 'all' THEN 'ALL'
    ELSE nr.protocol
  END AS protocol,
  CASE
    WHEN nr.protocol = '17' THEN
      CASE
        WHEN nr.udp_port_min IS NULL OR nr.udp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN nr.udp_port_min = nr.udp_port_max THEN TO_CHAR(nr.udp_port_min)
        ELSE TO_CHAR(nr.udp_port_min) || '-' || TO_CHAR(nr.udp_port_max)
      END
    ELSE
      CASE
        WHEN nr.tcp_port_min IS NULL OR nr.tcp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN nr.tcp_port_min = nr.tcp_port_max THEN TO_CHAR(nr.tcp_port_min)
        ELSE TO_CHAR(nr.tcp_port_min) || '-' || TO_CHAR(nr.tcp_port_max)
      END
  END AS destination_service_port
FROM vnic_target vt
JOIN subnet_details sd
  ON sd.subnet_id = vt.subnet_id
JOIN nsg_vnic_assoc nva
  ON nva.vnic_id = vt.vnic_id
JOIN nsg_rules nr
  ON nr.nsg_id = nva.nsg_id
 AND nr.direction = 'INGRESS'
LEFT JOIN nsg_data nd
  ON nd.nsg_id = nr.nsg_id
ORDER BY rule_source, policy_name, rule_id;


-- ============================================================================
-- IP Exposure Lookup (By IP Address)
-- Prompts for an IP address (private or public), resolves the target VNIC,
-- and returns all effective ingress rules from Security Lists and NSGs.
-- Includes VCN/Subnet context and source/destination service details per rule.
-- ============================================================================
WITH input_param AS (
  SELECT '&ip_address' AS ip_address FROM dual
),
ip_to_vnic AS (
  SELECT DISTINCT
    COALESCE(
      json_value(pi.data, '$."vnic_id"' RETURNING VARCHAR2(200)),
      json_value(pi.data, '$."vnic-id"' RETURNING VARCHAR2(200)),
      json_value(pi.data, '$."vnicId"' RETURNING VARCHAR2(200))
    ) AS vnic_id
  FROM PRIVATEIPS pi
  JOIN input_param p
    ON COALESCE(
         json_value(pi.data, '$."ip_address"' RETURNING VARCHAR2(64)),
         json_value(pi.data, '$."ipAddress"' RETURNING VARCHAR2(64))
       ) = p.ip_address
  UNION
  SELECT DISTINCT
    COALESCE(
      json_value(pi.data, '$."vnic_id"' RETURNING VARCHAR2(200)),
      json_value(pi.data, '$."vnic-id"' RETURNING VARCHAR2(200)),
      json_value(pi.data, '$."vnicId"' RETURNING VARCHAR2(200))
    ) AS vnic_id
  FROM PUBLICIPS pub
  JOIN input_param p
    ON COALESCE(
         json_value(pub.data, '$."ip_address"' RETURNING VARCHAR2(64)),
         json_value(pub.data, '$."ipAddress"' RETURNING VARCHAR2(64))
       ) = p.ip_address
  JOIN PRIVATEIPS pi
    ON COALESCE(
         json_value(pub.data, '$."private_ip_id"' RETURNING VARCHAR2(200)),
         json_value(pub.data, '$."privateIpId"' RETURNING VARCHAR2(200))
       ) = COALESCE(
         json_value(pi.data, '$."id"' RETURNING VARCHAR2(200)),
         json_value(pi.data, '$."identifier"' RETURNING VARCHAR2(200))
       )
),
vnic_target AS (
  SELECT
    json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) AS vnic_id,
    json_value(v.data, '$."display_name"' RETURNING VARCHAR2(200)) AS vnic_name,
    json_value(v.data, '$."additional_details"."subnetId"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(v.data, '$."additional_details"."privateIp"' RETURNING VARCHAR2(64)) AS private_ip,
    json_value(v.data, '$."additional_details"."publicIp"' RETURNING VARCHAR2(64)) AS public_ip
  FROM VNICS v
  JOIN ip_to_vnic t
    ON t.vnic_id = json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200))
),
subnet_details AS (
  SELECT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."vcnId"' RETURNING VARCHAR2(200)) AS vcn_id,
    REGEXP_SUBSTR(
      json_value(s.data, '$."additional_details"."subnetDomainName"' RETURNING VARCHAR2(500)),
      '\\.([^.]+)\\.oraclevcn\\.com$',
      1,
      1,
      NULL,
      1
    ) AS vcn_name
  FROM SUBNETS s
),
subnet_sl AS (
  SELECT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    sl_ids.securitylist_id
  FROM SUBNETS s
  CROSS APPLY json_table(
    s.data,
    '$."additional_details"."securityListIds"[*]'
    COLUMNS (
      securitylist_id VARCHAR2(200) PATH '$'
    )
  ) sl_ids
),
sl_rules AS (
  SELECT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id,
    json_value(sl.data, '$."display_name"' RETURNING VARCHAR2(200)) AS securitylist_name,
    r.rule_no,
    r.source,
    r.protocol,
    r.tcp_port_min,
    r.tcp_port_max,
    r.udp_port_min,
    r.udp_port_max
  FROM SECURITYLISTS sl
  CROSS APPLY json_table(
    sl.data,
    '$."additional_details"."ingressSecurityRules"[*]'
    COLUMNS (
      rule_no FOR ORDINALITY,
      source VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      tcp_port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"',
      udp_port_min NUMBER PATH '$."udpOptions"."destinationPortRange"."min"',
      udp_port_max NUMBER PATH '$."udpOptions"."destinationPortRange"."max"'
    )
  ) r
),
nsg_vnic_assoc AS (
  SELECT
    json_value(a.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(a.data, '$."vnic_id"' RETURNING VARCHAR2(200)) AS vnic_id
  FROM NSGVNIC a
),
nsg_data AS (
  SELECT
    COALESCE(
      json_value(n.data, '$."identifier"' RETURNING VARCHAR2(200)),
      json_value(n.data, '$."id"' RETURNING VARCHAR2(200))
    ) AS nsg_id,
    json_value(n.data, '$."display_name"' RETURNING VARCHAR2(200)) AS nsg_name
  FROM NSGDATA n
),
nsg_rules AS (
  SELECT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(r.data, '$."id"' RETURNING VARCHAR2(64)) AS rule_id,
    json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) AS direction,
    json_value(r.data, '$."source"' RETURNING VARCHAR2(64)) AS source,
    json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) AS protocol,
    json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) AS tcp_port_min,
    json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) AS tcp_port_max,
    json_value(r.data, '$."udp_options"."destination_port_range"."min"' RETURNING NUMBER) AS udp_port_min,
    json_value(r.data, '$."udp_options"."destination_port_range"."max"' RETURNING NUMBER) AS udp_port_max
  FROM NSGRULES r
)
SELECT
  vt.vnic_id,
  vt.vnic_name,
  vt.private_ip,
  vt.public_ip,
  sd.vcn_name,
  sd.vcn_id,
  sd.subnet_name,
  sd.subnet_id,
  'SECURITY_LIST' AS rule_source,
  slr.securitylist_name AS policy_name,
  slr.securitylist_id AS policy_id,
  TO_CHAR(slr.rule_no) AS rule_id,
  slr.source AS source_cidr,
  CASE
    WHEN slr.protocol = '6' THEN 'TCP'
    WHEN slr.protocol = '17' THEN 'UDP'
    WHEN slr.protocol = 'all' THEN 'ALL'
    ELSE slr.protocol
  END AS protocol,
  CASE
    WHEN slr.protocol = '17' THEN
      CASE
        WHEN slr.udp_port_min IS NULL OR slr.udp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN slr.udp_port_min = slr.udp_port_max THEN TO_CHAR(slr.udp_port_min)
        ELSE TO_CHAR(slr.udp_port_min) || '-' || TO_CHAR(slr.udp_port_max)
      END
    ELSE
      CASE
        WHEN slr.tcp_port_min IS NULL OR slr.tcp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN slr.tcp_port_min = slr.tcp_port_max THEN TO_CHAR(slr.tcp_port_min)
        ELSE TO_CHAR(slr.tcp_port_min) || '-' || TO_CHAR(slr.tcp_port_max)
      END
  END AS destination_service_port
FROM vnic_target vt
JOIN subnet_details sd
  ON sd.subnet_id = vt.subnet_id
JOIN subnet_sl ss
  ON ss.subnet_id = vt.subnet_id
JOIN sl_rules slr
  ON slr.securitylist_id = ss.securitylist_id
UNION ALL
SELECT
  vt.vnic_id,
  vt.vnic_name,
  vt.private_ip,
  vt.public_ip,
  sd.vcn_name,
  sd.vcn_id,
  sd.subnet_name,
  sd.subnet_id,
  'NSG' AS rule_source,
  nd.nsg_name AS policy_name,
  nr.nsg_id AS policy_id,
  nr.rule_id,
  nr.source AS source_cidr,
  CASE
    WHEN nr.protocol = '6' THEN 'TCP'
    WHEN nr.protocol = '17' THEN 'UDP'
    WHEN nr.protocol = 'all' THEN 'ALL'
    ELSE nr.protocol
  END AS protocol,
  CASE
    WHEN nr.protocol = '17' THEN
      CASE
        WHEN nr.udp_port_min IS NULL OR nr.udp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN nr.udp_port_min = nr.udp_port_max THEN TO_CHAR(nr.udp_port_min)
        ELSE TO_CHAR(nr.udp_port_min) || '-' || TO_CHAR(nr.udp_port_max)
      END
    ELSE
      CASE
        WHEN nr.tcp_port_min IS NULL OR nr.tcp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN nr.tcp_port_min = nr.tcp_port_max THEN TO_CHAR(nr.tcp_port_min)
        ELSE TO_CHAR(nr.tcp_port_min) || '-' || TO_CHAR(nr.tcp_port_max)
      END
  END AS destination_service_port
FROM vnic_target vt
JOIN subnet_details sd
  ON sd.subnet_id = vt.subnet_id
JOIN nsg_vnic_assoc nva
  ON nva.vnic_id = vt.vnic_id
JOIN nsg_rules nr
  ON nr.nsg_id = nva.nsg_id
 AND nr.direction = 'INGRESS'
LEFT JOIN nsg_data nd
  ON nd.nsg_id = nr.nsg_id
ORDER BY rule_source, policy_name, rule_id;
