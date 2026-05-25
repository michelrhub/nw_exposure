-- ============================================================================
-- Network Exposure - Internet Facing Query Pack (Oracle Autonomous Database)
--
-- Focus: internet-facing exposure in public networks.
-- This version intentionally removes explicit schema prefixes (e.g., ADMIN.).
--
-- Suggested usage:
--   1) Connect with a user that owns the tables, OR
--   2) Run: ALTER SESSION SET CURRENT_SCHEMA = <schema_name>;
-- ============================================================================


-- ============================================================================
-- In-Use Insecure Security Lists in Public Networks
-- Returns insecure security list rules (ALL ports - TCP/22 - TCP/3389) that are effectively used by public subnets.
-- ============================================================================
WITH igw_route_tables AS (
  SELECT DISTINCT
    json_value(r.data, '$."identifier"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM ROUTES r
  CROSS APPLY json_table(
    r.data,
    '$."additional_details"."routeRules"[*]'
    COLUMNS (
      network_entity_id VARCHAR2(4000) PATH '$."networkEntityId"'
    )
  ) rr
  WHERE rr.network_entity_id LIKE '%internetgateway%'
),
public_subnets AS (
  SELECT DISTINCT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200)) AS route_table_id,
    json_value(s.data, '$."additional_details"."prohibitPublicIpOnVnic"' RETURNING VARCHAR2(5)) AS prohibit_public_ip_on_vnic
  FROM SUBNETS s
  JOIN igw_route_tables igw
    ON igw.route_table_id = json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200))
  WHERE json_value(
          s.data,
          '$."additional_details"."prohibitPublicIpOnVnic"'
          RETURNING VARCHAR2(5)
        ) = 'false'
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
insecure_securitylists AS (
  SELECT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id,
    json_value(sl.data, '$."display_name"' RETURNING VARCHAR2(200)) AS securitylist_name,
    r.rule_no,
    CASE
      WHEN r.source = '0.0.0.0/0' AND (r.protocol = 'all' OR (r.protocol = '6' AND r.tcp_options_json IS NULL))
        THEN 'ALL'
      WHEN r.source = '0.0.0.0/0' AND r.protocol = '6'
       AND r.port_min IS NOT NULL AND r.port_max IS NOT NULL
       AND 22 BETWEEN r.port_min AND r.port_max
        THEN '22'
      WHEN r.source = '0.0.0.0/0' AND r.protocol = '6'
       AND r.port_min IS NOT NULL AND r.port_max IS NOT NULL
       AND 3389 BETWEEN r.port_min AND r.port_max
        THEN '3389'
    END AS insecure_case
  FROM SECURITYLISTS sl
  CROSS APPLY json_table(
    sl.data,
    '$."additional_details"."ingressSecurityRules"[*]'
    COLUMNS (
      rule_no FOR ORDINALITY,
      source   VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_options_json CLOB FORMAT JSON PATH '$."tcpOptions"',
      port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"'
    )
  ) r
  WHERE r.source = '0.0.0.0/0'
)
SELECT DISTINCT
  isl.securitylist_name,
  isl.securitylist_id,
  ps.subnet_name,
  ps.subnet_id,
  ps.prohibit_public_ip_on_vnic AS prohibitPublicIpOnVnic,
  ps.route_table_id,
  isl.rule_no AS insecure_rule_number,
  isl.insecure_case
FROM public_subnets ps
JOIN subnet_sl ss
  ON ss.subnet_id = ps.subnet_id
JOIN insecure_securitylists isl
  ON isl.securitylist_id = ss.securitylist_id
WHERE isl.insecure_case IS NOT NULL
ORDER BY ps.subnet_id, isl.securitylist_id, isl.rule_no, isl.insecure_case;


-- ============================================================================
-- In-Use Insecure NSGs on VNICs in Public Networks
-- Returns insecure NSG rules (ALL ports - TCP/22 - TCP/3389) attached to VNICs in public subnets.
-- ============================================================================
WITH igw_route_tables AS (
  SELECT DISTINCT
    json_value(r.data, '$."identifier"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM ROUTES r
  CROSS APPLY json_table(
    r.data,
    '$."additional_details"."routeRules"[*]'
    COLUMNS (
      network_entity_id VARCHAR2(4000) PATH '$."networkEntityId"'
    )
  ) rr
  WHERE rr.network_entity_id LIKE '%internetgateway%'
),
public_subnets AS (
  SELECT DISTINCT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM SUBNETS s
  JOIN igw_route_tables igw
    ON igw.route_table_id = json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200))
  WHERE json_value(
          s.data,
          '$."additional_details"."prohibitPublicIpOnVnic"'
          RETURNING VARCHAR2(5)
        ) = 'false'
),
insecure_nsg_rules AS (
  SELECT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(r.data, '$."id"'     RETURNING VARCHAR2(64))  AS rule_id,
    CASE
      WHEN json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
       AND json_value(r.data, '$."source"'    RETURNING VARCHAR2(64)) = '0.0.0.0/0'
       AND (
            json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = 'all'
            OR (
              json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
              AND json_query(r.data, '$."tcp_options"' RETURNING CLOB) IS NULL
            )
           )
      THEN 'ALL'
      WHEN json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
       AND json_value(r.data, '$."source"'    RETURNING VARCHAR2(64)) = '0.0.0.0/0'
       AND json_value(r.data, '$."protocol"'  RETURNING VARCHAR2(16)) = '6'
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) IS NOT NULL
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) IS NOT NULL
       AND 22 BETWEEN
           json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
      THEN '22'
      WHEN json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
       AND json_value(r.data, '$."source"'    RETURNING VARCHAR2(64)) = '0.0.0.0/0'
       AND json_value(r.data, '$."protocol"'  RETURNING VARCHAR2(16)) = '6'
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) IS NOT NULL
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) IS NOT NULL
       AND 3389 BETWEEN
           json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
       AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
      THEN '3389'
    END AS insecure_case
  FROM NSGRULES r
),
insecure_nsgs AS (
  SELECT nsg_id, rule_id, insecure_case
  FROM insecure_nsg_rules
  WHERE insecure_case IS NOT NULL
),
nsg_vnic_assoc AS (
  SELECT
    json_value(a.data, '$."nsg-id"'  RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(a.data, '$."vnic_id"' RETURNING VARCHAR2(200)) AS vnic_id
  FROM NSGVNIC a
),
vnic_data AS (
  SELECT
    json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) AS vnic_id,
    json_value(v.data, '$."display_name"' RETURNING VARCHAR2(200)) AS vnic_name,
    json_value(v.data, '$."additional_details"."subnetId"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(v.data, '$."additional_details"."privateIp"' RETURNING VARCHAR2(64)) AS private_ip,
    json_value(v.data, '$."additional_details"."publicIp"'  RETURNING VARCHAR2(64)) AS public_ip
  FROM VNICS v
)
SELECT DISTINCT
  vd.vnic_id,
  vd.vnic_name,
  vd.subnet_id,
  ps.subnet_name,
  ps.route_table_id,
  vd.private_ip,
  vd.public_ip,
  ina.nsg_id,
  ina.rule_id AS insecure_rule_id,
  ina.insecure_case
FROM insecure_nsgs ina
JOIN nsg_vnic_assoc nva
  ON nva.nsg_id = ina.nsg_id
JOIN vnic_data vd
  ON vd.vnic_id = nva.vnic_id
JOIN public_subnets ps
  ON ps.subnet_id = vd.subnet_id
ORDER BY vd.vnic_id, ina.nsg_id, ina.rule_id, ina.insecure_case;


-- ============================================================================
-- Public Insecure VNICs
-- Returns public-network VNICs exposed by insecure security lists and/or insecure NSGs.
-- (ALL ports - TCP/22 - TCP/3389)
-- ============================================================================
WITH igw_route_tables AS (
  SELECT DISTINCT
    json_value(r.data, '$."identifier"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM ROUTES r
  CROSS APPLY json_table(
    r.data,
    '$."additional_details"."routeRules"[*]'
    COLUMNS (
      network_entity_id VARCHAR2(4000) PATH '$."networkEntityId"'
    )
  ) rr
  WHERE rr.network_entity_id LIKE '%internetgateway%'
),
public_subnets AS (
  SELECT DISTINCT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM SUBNETS s
  JOIN igw_route_tables igw
    ON igw.route_table_id = json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200))
  WHERE json_value(
          s.data,
          '$."additional_details"."prohibitPublicIpOnVnic"'
          RETURNING VARCHAR2(5)
        ) = 'false'
),
vnic_data AS (
  SELECT
    json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) AS vnic_id,
    json_value(v.data, '$."display_name"' RETURNING VARCHAR2(200)) AS vnic_name,
    json_value(v.data, '$."additional_details"."subnetId"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(v.data, '$."additional_details"."privateIp"' RETURNING VARCHAR2(64)) AS private_ip,
    json_value(v.data, '$."additional_details"."publicIp"'  RETURNING VARCHAR2(64)) AS public_ip
  FROM VNICS v
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
insecure_securitylists AS (
  SELECT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id,
    CASE
      WHEN r.source = '0.0.0.0/0' AND (r.protocol = 'all' OR (r.protocol = '6' AND r.tcp_options_json IS NULL))
        THEN 'ALL'
      WHEN r.source = '0.0.0.0/0' AND r.protocol = '6'
       AND r.port_min IS NOT NULL AND r.port_max IS NOT NULL
       AND 22 BETWEEN r.port_min AND r.port_max
        THEN '22'
      WHEN r.source = '0.0.0.0/0' AND r.protocol = '6'
       AND r.port_min IS NOT NULL AND r.port_max IS NOT NULL
       AND 3389 BETWEEN r.port_min AND r.port_max
        THEN '3389'
    END AS insecure_case
  FROM SECURITYLISTS sl
  CROSS APPLY json_table(
    sl.data,
    '$."additional_details"."ingressSecurityRules"[*]'
    COLUMNS (
      source   VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_options_json CLOB FORMAT JSON PATH '$."tcpOptions"',
      port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"'
    )
  ) r
  WHERE r.source = '0.0.0.0/0'
),
insecure_nsgs AS (
  SELECT DISTINCT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    CASE
      WHEN json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
       AND json_value(r.data, '$."source"'    RETURNING VARCHAR2(64)) = '0.0.0.0/0'
       AND (
            json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = 'all'
            OR (
              json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
              AND json_query(r.data, '$."tcp_options"' RETURNING CLOB) IS NULL
            )
            OR (
              json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
              AND json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) IS NOT NULL
              AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) IS NOT NULL
              AND (
                22 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
                   AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
                OR
                3389 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
                     AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
              )
            )
           )
      THEN 'INSECURE'
    END AS insecure_flag
  FROM NSGRULES r
),
nsg_vnic_assoc AS (
  SELECT
    json_value(a.data, '$."nsg-id"'  RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(a.data, '$."vnic_id"' RETURNING VARCHAR2(200)) AS vnic_id
  FROM NSGVNIC a
),
vnics_exposed_by_sl AS (
  SELECT DISTINCT
    vd.vnic_id,
    'SECURITY_LIST' AS exposure_source
  FROM vnic_data vd
  JOIN public_subnets ps
    ON ps.subnet_id = vd.subnet_id
  JOIN subnet_sl ss
    ON ss.subnet_id = vd.subnet_id
  JOIN insecure_securitylists isl
    ON isl.securitylist_id = ss.securitylist_id
  WHERE isl.insecure_case IS NOT NULL
),
vnics_exposed_by_nsg AS (
  SELECT DISTINCT
    vd.vnic_id,
    'NSG' AS exposure_source
  FROM vnic_data vd
  JOIN public_subnets ps
    ON ps.subnet_id = vd.subnet_id
  JOIN nsg_vnic_assoc nva
    ON nva.vnic_id = vd.vnic_id
  JOIN insecure_nsgs insg
    ON insg.nsg_id = nva.nsg_id
  WHERE insg.insecure_flag = 'INSECURE'
),
public_insecure_vnics AS (
  SELECT * FROM vnics_exposed_by_sl
  UNION ALL
  SELECT * FROM vnics_exposed_by_nsg
)
SELECT DISTINCT
  vd.vnic_id,
  vd.vnic_name,
  vd.subnet_id,
  ps.subnet_name,
  ps.route_table_id,
  vd.private_ip,
  vd.public_ip,
  piv.exposure_source
FROM public_insecure_vnics piv
JOIN vnic_data vd
  ON vd.vnic_id = piv.vnic_id
JOIN public_subnets ps
  ON ps.subnet_id = vd.subnet_id
ORDER BY vd.vnic_id, piv.exposure_source;


-- ============================================================================
-- Public Insecure Subnets
-- Returns public subnets exposed by insecure security lists.
-- (ALL ports - TCP/22 - TCP/3389)
-- ============================================================================
WITH igw_route_tables AS (
  SELECT DISTINCT
    json_value(r.data, '$."identifier"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM ROUTES r
  CROSS APPLY json_table(
    r.data,
    '$."additional_details"."routeRules"[*]'
    COLUMNS (
      network_entity_id VARCHAR2(4000) PATH '$."networkEntityId"'
    )
  ) rr
  WHERE rr.network_entity_id LIKE '%internetgateway%'
),
public_subnets AS (
  SELECT DISTINCT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM SUBNETS s
  JOIN igw_route_tables igw
    ON igw.route_table_id = json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200))
  WHERE json_value(
          s.data,
          '$."additional_details"."prohibitPublicIpOnVnic"'
          RETURNING VARCHAR2(5)
        ) = 'false'
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
insecure_securitylists AS (
  SELECT DISTINCT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id
  FROM SECURITYLISTS sl
  CROSS APPLY json_table(
    sl.data,
    '$."additional_details"."ingressSecurityRules"[*]'
    COLUMNS (
      source   VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_options_json CLOB FORMAT JSON PATH '$."tcpOptions"',
      port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"'
    )
  ) r
  WHERE r.source = '0.0.0.0/0'
    AND (
      r.protocol = 'all'
      OR (r.protocol = '6' AND r.tcp_options_json IS NULL)
      OR (r.protocol = '6' AND r.port_min IS NOT NULL AND r.port_max IS NOT NULL
          AND (22 BETWEEN r.port_min AND r.port_max OR 3389 BETWEEN r.port_min AND r.port_max))
    )
),
insecure_nsgs AS (
  SELECT DISTINCT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id
  FROM NSGRULES r
  WHERE json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
    AND json_value(r.data, '$."source"'    RETURNING VARCHAR2(64)) = '0.0.0.0/0'
    AND (
      json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = 'all'
      OR (
        json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
        AND json_query(r.data, '$."tcp_options"' RETURNING CLOB) IS NULL
      )
      OR (
        json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
        AND json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) IS NOT NULL
        AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) IS NOT NULL
        AND (
          22 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
             AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
          OR
          3389 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
               AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
        )
      )
    )
),
nsg_vnic_assoc AS (
  SELECT
    json_value(a.data, '$."nsg-id"'  RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(a.data, '$."vnic_id"' RETURNING VARCHAR2(200)) AS vnic_id
  FROM NSGVNIC a
),
vnic_data AS (
  SELECT
    json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) AS vnic_id,
    json_value(v.data, '$."additional_details"."subnetId"' RETURNING VARCHAR2(200)) AS subnet_id
  FROM VNICS v
),
subnets_exposed_by_sl AS (
  SELECT DISTINCT
    ps.subnet_id,
    'SECURITY_LIST' AS exposure_source
  FROM public_subnets ps
  JOIN subnet_sl ss
    ON ss.subnet_id = ps.subnet_id
  JOIN insecure_securitylists isl
    ON isl.securitylist_id = ss.securitylist_id
),
subnets_exposed_by_nsg AS (
  SELECT DISTINCT
    ps.subnet_id,
    'NSG' AS exposure_source
  FROM public_subnets ps
  JOIN vnic_data vd
    ON vd.subnet_id = ps.subnet_id
  JOIN nsg_vnic_assoc nva
    ON nva.vnic_id = vd.vnic_id
  JOIN insecure_nsgs insg
    ON insg.nsg_id = nva.nsg_id
),
public_insecure_subnets AS (
  SELECT * FROM subnets_exposed_by_sl
  UNION ALL
  SELECT * FROM subnets_exposed_by_nsg
)
SELECT DISTINCT
  ps.subnet_id,
  ps.subnet_name,
  ps.route_table_id,
  pis.exposure_source
FROM public_insecure_subnets pis
JOIN public_subnets ps
  ON ps.subnet_id = pis.subnet_id
ORDER BY ps.subnet_id, pis.exposure_source;


-- ============================================================================
-- PART B - Other Exposed Ports/Protocols in Public Networks
-- Scope: public networks only, excluding ALL ports, TCP/22 and TCP/3389.
-- ============================================================================

-- ============================================================================
-- Summary of services used in public subnets and vnics
-- Returns protocol+service exposure summary in public networks, grouped by SECURITY_LIST or NSG.
-- Includes only:
--   - security lists effectively in use by public subnets
--   - NSGs effectively in use by VNICs in public subnets
-- Includes all services, including ALL ports, TCP/22 and TCP/3389.
-- ============================================================================
WITH igw_route_tables AS (
  SELECT DISTINCT
    json_value(r.data, '$."identifier"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM ROUTES r
  CROSS APPLY json_table(
    r.data,
    '$."additional_details"."routeRules"[*]'
    COLUMNS (
      network_entity_id VARCHAR2(4000) PATH '$."networkEntityId"'
    )
  ) rr
  WHERE rr.network_entity_id LIKE '%internetgateway%'
),
public_subnets AS (
  SELECT DISTINCT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id
  FROM SUBNETS s
  JOIN igw_route_tables igw
    ON igw.route_table_id = json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200))
  WHERE json_value(
          s.data,
          '$."additional_details"."prohibitPublicIpOnVnic"'
          RETURNING VARCHAR2(5)
        ) = 'false'
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
other_securitylist_rules AS (
  SELECT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id,
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
      source   VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_options_json CLOB FORMAT JSON PATH '$."tcpOptions"',
      tcp_port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      tcp_port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"',
      udp_port_min NUMBER PATH '$."udpOptions"."destinationPortRange"."min"',
      udp_port_max NUMBER PATH '$."udpOptions"."destinationPortRange"."max"'
    )
  ) r
  WHERE r.source = '0.0.0.0/0'
),
other_nsg_rules AS (
  SELECT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) AS protocol,
    json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) AS tcp_port_min,
    json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) AS tcp_port_max,
    json_value(r.data, '$."udp_options"."destination_port_range"."min"' RETURNING NUMBER) AS udp_port_min,
    json_value(r.data, '$."udp_options"."destination_port_range"."max"' RETURNING NUMBER) AS udp_port_max
  FROM NSGRULES r
  WHERE json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
    AND json_value(r.data, '$."source"' RETURNING VARCHAR2(64)) = '0.0.0.0/0'
),
nsg_vnic_assoc AS (
  SELECT
    json_value(a.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(a.data, '$."vnic_id"' RETURNING VARCHAR2(200)) AS vnic_id
  FROM NSGVNIC a
),
vnic_data AS (
  SELECT
    json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) AS vnic_id,
    json_value(v.data, '$."additional_details"."subnetId"' RETURNING VARCHAR2(200)) AS subnet_id
  FROM VNICS v
),
services_from_sl AS (
  SELECT
    'SECURITY_LIST' AS exposure_source,
    osr.protocol,
    osr.tcp_port_min,
    osr.tcp_port_max,
    osr.udp_port_min,
    osr.udp_port_max
  FROM public_subnets ps
  JOIN subnet_sl ss
    ON ss.subnet_id = ps.subnet_id
  JOIN other_securitylist_rules osr
    ON osr.securitylist_id = ss.securitylist_id
),
services_from_nsg AS (
  SELECT
    'NSG' AS exposure_source,
    onr.protocol,
    onr.tcp_port_min,
    onr.tcp_port_max,
    onr.udp_port_min,
    onr.udp_port_max
  FROM public_subnets ps
  JOIN vnic_data vd
    ON vd.subnet_id = ps.subnet_id
  JOIN nsg_vnic_assoc nva
    ON nva.vnic_id = vd.vnic_id
  JOIN other_nsg_rules onr
    ON onr.nsg_id = nva.nsg_id
),
all_services AS (
  SELECT * FROM services_from_sl
  UNION ALL
  SELECT * FROM services_from_nsg
)
SELECT
  exposure_source,
  CASE
    WHEN protocol = '6' THEN 'TCP'
    WHEN protocol = '17' THEN 'UDP'
    ELSE protocol
  END AS protocol,
  CASE
    WHEN protocol = '17' THEN
      CASE
        WHEN udp_port_min IS NULL OR udp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN udp_port_min = udp_port_max THEN TO_CHAR(udp_port_min)
        ELSE TO_CHAR(udp_port_min) || '-' || TO_CHAR(udp_port_max)
      END
    ELSE
      CASE
        WHEN tcp_port_min IS NULL OR tcp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN tcp_port_min = tcp_port_max THEN TO_CHAR(tcp_port_min)
        ELSE TO_CHAR(tcp_port_min) || '-' || TO_CHAR(tcp_port_max)
      END
  END AS service,
  COUNT(*) AS total_occurrences
FROM all_services
GROUP BY
  exposure_source,
  CASE
    WHEN protocol = '6' THEN 'TCP'
    WHEN protocol = '17' THEN 'UDP'
    ELSE protocol
  END,
  CASE
    WHEN protocol = '17' THEN
      CASE
        WHEN udp_port_min IS NULL OR udp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN udp_port_min = udp_port_max THEN TO_CHAR(udp_port_min)
        ELSE TO_CHAR(udp_port_min) || '-' || TO_CHAR(udp_port_max)
      END
    ELSE
      CASE
        WHEN tcp_port_min IS NULL OR tcp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN tcp_port_min = tcp_port_max THEN TO_CHAR(tcp_port_min)
        ELSE TO_CHAR(tcp_port_min) || '-' || TO_CHAR(tcp_port_max)
      END
  END
ORDER BY exposure_source, total_occurrences DESC, protocol, service;


-- ============================================================================
-- In-Use Other Security Lists in Public Networks
-- Returns security list rules in use by public subnets excluding ALL ports, TCP/22 or TCP/3389.
-- ============================================================================
WITH igw_route_tables AS (
  SELECT DISTINCT
    json_value(r.data, '$."identifier"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM ROUTES r
  CROSS APPLY json_table(
    r.data,
    '$."additional_details"."routeRules"[*]'
    COLUMNS (
      network_entity_id VARCHAR2(4000) PATH '$."networkEntityId"'
    )
  ) rr
  WHERE rr.network_entity_id LIKE '%internetgateway%'
),
public_subnets AS (
  SELECT DISTINCT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200)) AS route_table_id,
    json_value(s.data, '$."additional_details"."prohibitPublicIpOnVnic"' RETURNING VARCHAR2(5)) AS prohibit_public_ip_on_vnic
  FROM SUBNETS s
  JOIN igw_route_tables igw
    ON igw.route_table_id = json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200))
  WHERE json_value(
          s.data,
          '$."additional_details"."prohibitPublicIpOnVnic"'
          RETURNING VARCHAR2(5)
        ) = 'false'
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
other_securitylists AS (
  SELECT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id,
    json_value(sl.data, '$."display_name"' RETURNING VARCHAR2(200)) AS securitylist_name,
    r.rule_no,
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
      source   VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_options_json CLOB FORMAT JSON PATH '$."tcpOptions"',
      tcp_port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      tcp_port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"',
      udp_port_min NUMBER PATH '$."udpOptions"."destinationPortRange"."min"',
      udp_port_max NUMBER PATH '$."udpOptions"."destinationPortRange"."max"'
    )
  ) r
  WHERE r.source = '0.0.0.0/0'
    AND NOT (
      r.protocol = 'all'
      OR (r.protocol = '6' AND r.tcp_options_json IS NULL)
      OR (r.protocol = '6'
          AND r.tcp_port_min IS NOT NULL AND r.tcp_port_max IS NOT NULL
          AND (22 BETWEEN r.tcp_port_min AND r.tcp_port_max
            OR 3389 BETWEEN r.tcp_port_min AND r.tcp_port_max))
    )
)
SELECT DISTINCT
  osl.securitylist_name,
  osl.securitylist_id,
  ps.subnet_name,
  ps.subnet_id,
  ps.prohibit_public_ip_on_vnic AS prohibitPublicIpOnVnic,
  ps.route_table_id,
  osl.rule_no AS rule_number,
  CASE
    WHEN osl.protocol = '6' THEN 'TCP'
    WHEN osl.protocol = '17' THEN 'UDP'
    ELSE osl.protocol
  END AS protocol,
  CASE
    WHEN osl.protocol = '17' THEN
      CASE
        WHEN osl.udp_port_min IS NULL OR osl.udp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN osl.udp_port_min = osl.udp_port_max THEN TO_CHAR(osl.udp_port_min)
        ELSE TO_CHAR(osl.udp_port_min) || '-' || TO_CHAR(osl.udp_port_max)
      END
    ELSE
      CASE
        WHEN osl.tcp_port_min IS NULL OR osl.tcp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN osl.tcp_port_min = osl.tcp_port_max THEN TO_CHAR(osl.tcp_port_min)
        ELSE TO_CHAR(osl.tcp_port_min) || '-' || TO_CHAR(osl.tcp_port_max)
      END
  END AS service
FROM public_subnets ps
JOIN subnet_sl ss
  ON ss.subnet_id = ps.subnet_id
JOIN other_securitylists osl
  ON osl.securitylist_id = ss.securitylist_id
ORDER BY ps.subnet_id, osl.securitylist_id, osl.rule_no;


-- ============================================================================
-- In-Use Other NSGs on VNICs in Public Networks
-- Returns NSG rules in use by VNICs in public subnets excluding ALL ports, TCP/22 or TCP/3389.
-- ============================================================================
WITH igw_route_tables AS (
  SELECT DISTINCT
    json_value(r.data, '$."identifier"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM ROUTES r
  CROSS APPLY json_table(
    r.data,
    '$."additional_details"."routeRules"[*]'
    COLUMNS (
      network_entity_id VARCHAR2(4000) PATH '$."networkEntityId"'
    )
  ) rr
  WHERE rr.network_entity_id LIKE '%internetgateway%'
),
public_subnets AS (
  SELECT DISTINCT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM SUBNETS s
  JOIN igw_route_tables igw
    ON igw.route_table_id = json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200))
  WHERE json_value(
          s.data,
          '$."additional_details"."prohibitPublicIpOnVnic"'
          RETURNING VARCHAR2(5)
        ) = 'false'
),
other_nsg_rules AS (
  SELECT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(r.data, '$."id"' RETURNING VARCHAR2(64)) AS rule_id,
    json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) AS protocol,
    json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) AS tcp_port_min,
    json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) AS tcp_port_max,
    json_value(r.data, '$."udp_options"."destination_port_range"."min"' RETURNING NUMBER) AS udp_port_min,
    json_value(r.data, '$."udp_options"."destination_port_range"."max"' RETURNING NUMBER) AS udp_port_max
  FROM NSGRULES r
  WHERE json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
    AND json_value(r.data, '$."source"' RETURNING VARCHAR2(64)) = '0.0.0.0/0'
    AND NOT (
      json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = 'all'
      OR (
        json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
        AND json_query(r.data, '$."tcp_options"' RETURNING CLOB) IS NULL
      )
      OR (
        json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
        AND json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) IS NOT NULL
        AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) IS NOT NULL
        AND (
          22 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
             AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
          OR
          3389 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
               AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
        )
      )
    )
),
nsg_vnic_assoc AS (
  SELECT
    json_value(a.data, '$."nsg-id"'  RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(a.data, '$."vnic_id"' RETURNING VARCHAR2(200)) AS vnic_id
  FROM NSGVNIC a
),
vnic_data AS (
  SELECT
    json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) AS vnic_id,
    json_value(v.data, '$."display_name"' RETURNING VARCHAR2(200)) AS vnic_name,
    json_value(v.data, '$."additional_details"."subnetId"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(v.data, '$."additional_details"."privateIp"' RETURNING VARCHAR2(64)) AS private_ip,
    json_value(v.data, '$."additional_details"."publicIp"'  RETURNING VARCHAR2(64)) AS public_ip
  FROM VNICS v
)
SELECT DISTINCT
  vd.vnic_id,
  vd.vnic_name,
  vd.subnet_id,
  ps.subnet_name,
  ps.route_table_id,
  vd.private_ip,
  vd.public_ip,
  onr.nsg_id,
  onr.rule_id,
  CASE
    WHEN onr.protocol = '6' THEN 'TCP'
    WHEN onr.protocol = '17' THEN 'UDP'
    ELSE onr.protocol
  END AS protocol,
  CASE
    WHEN onr.protocol = '17' THEN
      CASE
        WHEN onr.udp_port_min IS NULL OR onr.udp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN onr.udp_port_min = onr.udp_port_max THEN TO_CHAR(onr.udp_port_min)
        ELSE TO_CHAR(onr.udp_port_min) || '-' || TO_CHAR(onr.udp_port_max)
      END
    ELSE
      CASE
        WHEN onr.tcp_port_min IS NULL OR onr.tcp_port_max IS NULL THEN 'ALL_PORTS'
        WHEN onr.tcp_port_min = onr.tcp_port_max THEN TO_CHAR(onr.tcp_port_min)
        ELSE TO_CHAR(onr.tcp_port_min) || '-' || TO_CHAR(onr.tcp_port_max)
      END
  END AS service
FROM other_nsg_rules onr
JOIN nsg_vnic_assoc nva
  ON nva.nsg_id = onr.nsg_id
JOIN vnic_data vd
  ON vd.vnic_id = nva.vnic_id
JOIN public_subnets ps
  ON ps.subnet_id = vd.subnet_id
ORDER BY vd.vnic_id, onr.nsg_id, onr.rule_id;


-- ============================================================================
-- Public VNICs Exposed by Other Ports/Protocols
-- Returns public-network VNICs exposed by security lists and/or NSGs rules excluding ALL ports, TCP/22 or TCP/3389.
-- ============================================================================
WITH igw_route_tables AS (
  SELECT DISTINCT
    json_value(r.data, '$."identifier"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM ROUTES r
  CROSS APPLY json_table(
    r.data,
    '$."additional_details"."routeRules"[*]'
    COLUMNS (
      network_entity_id VARCHAR2(4000) PATH '$."networkEntityId"'
    )
  ) rr
  WHERE rr.network_entity_id LIKE '%internetgateway%'
),
public_subnets AS (
  SELECT DISTINCT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM SUBNETS s
  JOIN igw_route_tables igw
    ON igw.route_table_id = json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200))
  WHERE json_value(
          s.data,
          '$."additional_details"."prohibitPublicIpOnVnic"'
          RETURNING VARCHAR2(5)
        ) = 'false'
),
vnic_data AS (
  SELECT
    json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) AS vnic_id,
    json_value(v.data, '$."display_name"' RETURNING VARCHAR2(200)) AS vnic_name,
    json_value(v.data, '$."additional_details"."subnetId"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(v.data, '$."additional_details"."privateIp"' RETURNING VARCHAR2(64)) AS private_ip,
    json_value(v.data, '$."additional_details"."publicIp"'  RETURNING VARCHAR2(64)) AS public_ip
  FROM VNICS v
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
other_securitylists AS (
  SELECT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id
  FROM SECURITYLISTS sl
  CROSS APPLY json_table(
    sl.data,
    '$."additional_details"."ingressSecurityRules"[*]'
    COLUMNS (
      source   VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_options_json CLOB FORMAT JSON PATH '$."tcpOptions"',
      tcp_port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      tcp_port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"'
    )
  ) r
  WHERE r.source = '0.0.0.0/0'
    AND NOT (
      r.protocol = 'all'
      OR (r.protocol = '6' AND r.tcp_options_json IS NULL)
      OR (r.protocol = '6'
          AND r.tcp_port_min IS NOT NULL AND r.tcp_port_max IS NOT NULL
          AND (22 BETWEEN r.tcp_port_min AND r.tcp_port_max
            OR 3389 BETWEEN r.tcp_port_min AND r.tcp_port_max))
    )
),
other_nsgs AS (
  SELECT DISTINCT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id
  FROM NSGRULES r
  WHERE json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
    AND json_value(r.data, '$."source"'    RETURNING VARCHAR2(64)) = '0.0.0.0/0'
    AND NOT (
      json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = 'all'
      OR (
        json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
        AND json_query(r.data, '$."tcp_options"' RETURNING CLOB) IS NULL
      )
      OR (
        json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
        AND json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) IS NOT NULL
        AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) IS NOT NULL
        AND (
          22 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
             AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
          OR
          3389 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
               AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
        )
      )
    )
),
nsg_vnic_assoc AS (
  SELECT
    json_value(a.data, '$."nsg-id"'  RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(a.data, '$."vnic_id"' RETURNING VARCHAR2(200)) AS vnic_id
  FROM NSGVNIC a
),
vnics_exposed_by_sl AS (
  SELECT DISTINCT
    vd.vnic_id,
    'SECURITY_LIST' AS exposure_source
  FROM vnic_data vd
  JOIN public_subnets ps
    ON ps.subnet_id = vd.subnet_id
  JOIN subnet_sl ss
    ON ss.subnet_id = vd.subnet_id
  JOIN other_securitylists osl
    ON osl.securitylist_id = ss.securitylist_id
),
vnics_exposed_by_nsg AS (
  SELECT DISTINCT
    vd.vnic_id,
    'NSG' AS exposure_source
  FROM vnic_data vd
  JOIN public_subnets ps
    ON ps.subnet_id = vd.subnet_id
  JOIN nsg_vnic_assoc nva
    ON nva.vnic_id = vd.vnic_id
  JOIN other_nsgs ons
    ON ons.nsg_id = nva.nsg_id
),
public_other_exposed_vnics AS (
  SELECT * FROM vnics_exposed_by_sl
  UNION ALL
  SELECT * FROM vnics_exposed_by_nsg
)
SELECT DISTINCT
  vd.vnic_id,
  vd.vnic_name,
  vd.subnet_id,
  ps.subnet_name,
  ps.route_table_id,
  vd.private_ip,
  vd.public_ip,
  pov.exposure_source
FROM public_other_exposed_vnics pov
JOIN vnic_data vd
  ON vd.vnic_id = pov.vnic_id
JOIN public_subnets ps
  ON ps.subnet_id = vd.subnet_id
ORDER BY vd.vnic_id, pov.exposure_source;


-- ============================================================================
-- Public Subnets Exposed by Other Ports/Protocols
-- Returns public subnets exposed by security lists and/or NSGs rules excluding ALL ports, TCP/22 or TCP/3389.
-- ============================================================================
WITH igw_route_tables AS (
  SELECT DISTINCT
    json_value(r.data, '$."identifier"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM ROUTES r
  CROSS APPLY json_table(
    r.data,
    '$."additional_details"."routeRules"[*]'
    COLUMNS (
      network_entity_id VARCHAR2(4000) PATH '$."networkEntityId"'
    )
  ) rr
  WHERE rr.network_entity_id LIKE '%internetgateway%'
),
public_subnets AS (
  SELECT DISTINCT
    json_value(s.data, '$."identifier"' RETURNING VARCHAR2(200)) AS subnet_id,
    json_value(s.data, '$."display_name"' RETURNING VARCHAR2(200)) AS subnet_name,
    json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200)) AS route_table_id
  FROM SUBNETS s
  JOIN igw_route_tables igw
    ON igw.route_table_id = json_value(s.data, '$."additional_details"."routeTableId"' RETURNING VARCHAR2(200))
  WHERE json_value(
          s.data,
          '$."additional_details"."prohibitPublicIpOnVnic"'
          RETURNING VARCHAR2(5)
        ) = 'false'
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
other_securitylists AS (
  SELECT DISTINCT
    json_value(sl.data, '$."identifier"' RETURNING VARCHAR2(200)) AS securitylist_id
  FROM SECURITYLISTS sl
  CROSS APPLY json_table(
    sl.data,
    '$."additional_details"."ingressSecurityRules"[*]'
    COLUMNS (
      source   VARCHAR2(64) PATH '$."source"',
      protocol VARCHAR2(16) PATH '$."protocol"',
      tcp_options_json CLOB FORMAT JSON PATH '$."tcpOptions"',
      tcp_port_min NUMBER PATH '$."tcpOptions"."destinationPortRange"."min"',
      tcp_port_max NUMBER PATH '$."tcpOptions"."destinationPortRange"."max"'
    )
  ) r
  WHERE r.source = '0.0.0.0/0'
    AND NOT (
      r.protocol = 'all'
      OR (r.protocol = '6' AND r.tcp_options_json IS NULL)
      OR (r.protocol = '6'
          AND r.tcp_port_min IS NOT NULL AND r.tcp_port_max IS NOT NULL
          AND (22 BETWEEN r.tcp_port_min AND r.tcp_port_max
            OR 3389 BETWEEN r.tcp_port_min AND r.tcp_port_max))
    )
),
other_nsgs AS (
  SELECT DISTINCT
    json_value(r.data, '$."nsg-id"' RETURNING VARCHAR2(200)) AS nsg_id
  FROM NSGRULES r
  WHERE json_value(r.data, '$."direction"' RETURNING VARCHAR2(16)) = 'INGRESS'
    AND json_value(r.data, '$."source"'    RETURNING VARCHAR2(64)) = '0.0.0.0/0'
    AND NOT (
      json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = 'all'
      OR (
        json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
        AND json_query(r.data, '$."tcp_options"' RETURNING CLOB) IS NULL
      )
      OR (
        json_value(r.data, '$."protocol"' RETURNING VARCHAR2(16)) = '6'
        AND json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER) IS NOT NULL
        AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER) IS NOT NULL
        AND (
          22 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
             AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
          OR
          3389 BETWEEN json_value(r.data, '$."tcp_options"."destination_port_range"."min"' RETURNING NUMBER)
               AND json_value(r.data, '$."tcp_options"."destination_port_range"."max"' RETURNING NUMBER)
        )
      )
    )
),
nsg_vnic_assoc AS (
  SELECT
    json_value(a.data, '$."nsg-id"'  RETURNING VARCHAR2(200)) AS nsg_id,
    json_value(a.data, '$."vnic_id"' RETURNING VARCHAR2(200)) AS vnic_id
  FROM NSGVNIC a
),
vnic_data AS (
  SELECT
    json_value(v.data, '$."identifier"' RETURNING VARCHAR2(200)) AS vnic_id,
    json_value(v.data, '$."additional_details"."subnetId"' RETURNING VARCHAR2(200)) AS subnet_id
  FROM VNICS v
),
subnets_exposed_by_sl AS (
  SELECT DISTINCT
    ps.subnet_id,
    'SECURITY_LIST' AS exposure_source
  FROM public_subnets ps
  JOIN subnet_sl ss
    ON ss.subnet_id = ps.subnet_id
  JOIN other_securitylists osl
    ON osl.securitylist_id = ss.securitylist_id
),
subnets_exposed_by_nsg AS (
  SELECT DISTINCT
    ps.subnet_id,
    'NSG' AS exposure_source
  FROM public_subnets ps
  JOIN vnic_data vd
    ON vd.subnet_id = ps.subnet_id
  JOIN nsg_vnic_assoc nva
    ON nva.vnic_id = vd.vnic_id
  JOIN other_nsgs ons
    ON ons.nsg_id = nva.nsg_id
),
public_other_exposed_subnets AS (
  SELECT * FROM subnets_exposed_by_sl
  UNION ALL
  SELECT * FROM subnets_exposed_by_nsg
)
SELECT DISTINCT
  ps.subnet_id,
  ps.subnet_name,
  ps.route_table_id,
  pos.exposure_source
FROM public_other_exposed_subnets pos
JOIN public_subnets ps
  ON ps.subnet_id = pos.subnet_id
ORDER BY ps.subnet_id, pos.exposure_source;
