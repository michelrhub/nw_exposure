#!/usr/bin/env python3
"""Next-gen all-in-one OCI exporter (turbo, JSONL).

Exports in a single run (parallel by region):
- nsgdata, nsgrules, nsgvnic
- securitylists
- publicips, privateips
- subnets, vnics, routes

Consolidated outputs:
- nsgdata.jsonl
- nsgrules.jsonl
- nsgvnic.jsonl
- securitylists.jsonl
- publicips.jsonl
- privateips.jsonl
- subnets.jsonl
- vnics.jsonl
- routes.jsonl
"""

import argparse
import concurrent.futures
import json
import os
import time
from pathlib import Path
from typing import Callable, Optional, Tuple

import oci
from oci.core import VirtualNetworkClient
from oci.exceptions import ServiceError
from oci.identity import IdentityClient
from oci.resource_search import ResourceSearchClient
from oci.resource_search.models import StructuredSearchDetails

DEFAULT_LIMIT = 1000
DEFAULT_SKIP_REGION = "us-saltlake-1"

NSG_QUERY = "query networksecuritygroup resources return allAdditionalFields"
SECURITYLIST_QUERY = "query securitylist resources return allAdditionalFields"
SUBNET_QUERY = "query subnet resources return allAdditionalFields"
VNIC_QUERY = "query vnic resources return allAdditionalFields"
ROUTES_QUERY = "query routetable resources return routerules"
PUBLICIP_QUERY = "query publicip resources return identifier"

RESOURCE_BASENAMES = (
    "nsgdata",
    "nsgrules",
    "nsgvnic",
    "securitylists",
    "publicips",
    "privateips",
    "subnets",
    "vnics",
    "routes",
)


def create_signer(
    config_file: str,
    profile: str,
    is_instance_principals: bool,
    is_delegation_token: bool,
    is_security_token: bool,
) -> Tuple[dict, object]:
    if is_instance_principals:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        return {"region": signer.region, "tenancy": signer.tenancy_id}, signer

    if is_delegation_token:
        env_config_file = os.environ.get("OCI_CONFIG_FILE")
        env_config_profile = os.environ.get("OCI_CONFIG_PROFILE")

        if not env_config_file or not env_config_profile:
            raise RuntimeError(
                "Cloud Shell auth (-dt) requires OCI_CONFIG_FILE and OCI_CONFIG_PROFILE environment variables."
            )

        config = oci.config.from_file(env_config_file, env_config_profile)
        token_path = config.get("delegation_token_file")
        if not token_path:
            raise RuntimeError("delegation_token_file was not found in OCI config profile.")

        with open(token_path, "r", encoding="utf-8") as fp:
            delegation_token = fp.read().strip()

        signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
            delegation_token=delegation_token
        )
        return config, signer

    if is_security_token:
        config = oci.config.from_file(config_file, profile)
        token_file = config.get("security_token_file")
        if not token_file:
            raise RuntimeError("security_token_file was not found in OCI config profile.")

        with open(token_file, "r", encoding="utf-8") as fp:
            token = fp.read()

        private_key = oci.signer.load_private_key_from_file(config["key_file"])
        signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
        return config, signer

    config = oci.config.from_file(config_file, profile)
    signer = oci.signer.Signer(
        tenancy=config["tenancy"],
        user=config["user"],
        fingerprint=config["fingerprint"],
        private_key_file_location=config.get("key_file"),
        pass_phrase=oci.config.get_config_value_or_default(config, "pass_phrase"),
        private_key_content=config.get("key_content"),
    )
    return config, signer


def is_throttle(exc: ServiceError) -> bool:
    return exc.status == 429 or exc.code in {
        "TooManyRequests",
        "LimitExceeded",
        "QuotaExceeded",
    }


def with_throttle_backoff(
    fn: Callable,
    *args,
    max_throttle_retries: int,
    backoff_base: float,
    **kwargs,
):
    attempts = 0
    while True:
        try:
            return fn(*args, **kwargs)
        except ServiceError as exc:
            if not is_throttle(exc) or attempts >= max_throttle_retries:
                raise
            sleep_s = min(30.0, backoff_base * (2**attempts))
            time.sleep(sleep_s)
            attempts += 1


def append_jsonl(path: Path, records: list[dict]) -> None:
    if not records:
        return
    with path.open("a", encoding="utf-8") as fp:
        for record in records:
            fp.write(json.dumps(record, ensure_ascii=False))
            fp.write("\n")


def consolidate_outputs(
    output_dir: Path,
    tenancy_id: str,
    regions: list[str],
    keep_regional_files: bool,
) -> None:
    for base in RESOURCE_BASENAMES:
        consolidated = output_dir / f"{base}.jsonl"
        consolidated.write_text("", encoding="utf-8")

        with consolidated.open("a", encoding="utf-8") as out_fp:
            for region_name in regions:
                regional = output_dir / f"{base}-{tenancy_id}-{region_name}.jsonl"
                if not regional.exists():
                    continue

                with regional.open("r", encoding="utf-8") as in_fp:
                    for line in in_fp:
                        out_fp.write(line)

                if not keep_regional_files:
                    regional.unlink()


def paginate_search_query(
    search_client: ResourceSearchClient,
    query_text: str,
    limit: int,
    max_throttle_retries: int,
    backoff_base: float,
) -> list[dict]:
    items: list[dict] = []
    next_page: Optional[str] = None

    while True:
        response = with_throttle_backoff(
            search_client.search_resources,
            StructuredSearchDetails(query=query_text),
            limit=limit,
            page=next_page,
            max_throttle_retries=max_throttle_retries,
            backoff_base=backoff_base,
        )

        for item in response.data.items:
            items.append(oci.util.to_dict(item))

        next_page = response.headers.get("opc-next-page")
        if not next_page:
            break

    return items


def paginate_search_identifiers(
    search_client: ResourceSearchClient,
    query_text: str,
    limit: int,
    max_throttle_retries: int,
    backoff_base: float,
) -> list[str]:
    ids: list[str] = []
    next_page: Optional[str] = None

    while True:
        response = with_throttle_backoff(
            search_client.search_resources,
            StructuredSearchDetails(query=query_text),
            limit=limit,
            page=next_page,
            max_throttle_retries=max_throttle_retries,
            backoff_base=backoff_base,
        )

        for item in response.data.items:
            if item.identifier:
                ids.append(item.identifier)

        next_page = response.headers.get("opc-next-page")
        if not next_page:
            break

    return ids


def paginate_nsg_rules(
    network_client: VirtualNetworkClient,
    nsg_id: str,
    region_name: str,
    limit: int,
    max_throttle_retries: int,
    backoff_base: float,
) -> list[dict]:
    items: list[dict] = []
    next_page: Optional[str] = None

    while True:
        response = with_throttle_backoff(
            network_client.list_network_security_group_security_rules,
            network_security_group_id=nsg_id,
            limit=limit,
            page=next_page,
            max_throttle_retries=max_throttle_retries,
            backoff_base=backoff_base,
        )

        for item in response.data:
            record = oci.util.to_dict(item)
            record["region"] = region_name
            record["nsg-id"] = nsg_id
            items.append(record)

        next_page = response.headers.get("opc-next-page")
        if not next_page:
            break

    return items


def paginate_nsg_vnics(
    network_client: VirtualNetworkClient,
    nsg_id: str,
    region_name: str,
    limit: int,
    max_throttle_retries: int,
    backoff_base: float,
) -> list[dict]:
    items: list[dict] = []
    next_page: Optional[str] = None

    while True:
        response = with_throttle_backoff(
            network_client.list_network_security_group_vnics,
            network_security_group_id=nsg_id,
            limit=limit,
            page=next_page,
            max_throttle_retries=max_throttle_retries,
            backoff_base=backoff_base,
        )

        for item in response.data:
            record = oci.util.to_dict(item)
            record["region"] = region_name
            record["nsg-id"] = nsg_id
            items.append(record)

        next_page = response.headers.get("opc-next-page")
        if not next_page:
            break

    return items


def fetch_public_ip_details(
    network_client: VirtualNetworkClient,
    public_ip_ids: list[str],
    region_name: str,
    max_throttle_retries: int,
    backoff_base: float,
) -> tuple[list[dict], int]:
    items: list[dict] = []
    skipped_404 = 0

    seen_ids: set[str] = set()
    for public_ip_id in public_ip_ids:
        if not public_ip_id or public_ip_id in seen_ids:
            continue
        seen_ids.add(public_ip_id)

        try:
            detail = with_throttle_backoff(
                network_client.get_public_ip,
                public_ip_id=public_ip_id,
                max_throttle_retries=max_throttle_retries,
                backoff_base=backoff_base,
            )
        except ServiceError as exc:
            if exc.status == 404:
                skipped_404 += 1
                continue
            raise

        record = oci.util.to_dict(detail.data)
        record["region"] = region_name
        items.append(record)

    return items, skipped_404


def fetch_private_ips_by_subnets(
    network_client: VirtualNetworkClient,
    subnet_records: list[dict],
    region_name: str,
    limit: int,
    max_throttle_retries: int,
    backoff_base: float,
) -> tuple[list[dict], int]:
    items: list[dict] = []
    skipped_404 = 0

    seen_subnet_ids: set[str] = set()
    for subnet in subnet_records:
        subnet_id = subnet.get("identifier")
        if not subnet_id or subnet_id in seen_subnet_ids:
            continue
        seen_subnet_ids.add(subnet_id)

        next_page: Optional[str] = None
        while True:
            try:
                response = with_throttle_backoff(
                    network_client.list_private_ips,
                    subnet_id=subnet_id,
                    limit=limit,
                    page=next_page,
                    max_throttle_retries=max_throttle_retries,
                    backoff_base=backoff_base,
                )
            except ServiceError as exc:
                if exc.status == 404:
                    skipped_404 += 1
                    break
                raise

            for item in response.data:
                record = oci.util.to_dict(item)
                record["region"] = region_name
                record["subnet-id"] = subnet_id
                compartment_id = subnet.get("compartment-id", "")
                if compartment_id:
                    record["subnet-compartment-id"] = compartment_id
                items.append(record)

            next_page = response.headers.get("opc-next-page")
            if not next_page:
                break

    return items, skipped_404


def export_region(
    region_name: str,
    base_config: dict,
    signer: object,
    tenancy_id: str,
    limit: int,
    output_dir: Path,
    max_throttle_retries: int,
    backoff_base: float,
) -> Tuple[str, dict, int, Optional[str]]:
    region_config = dict(base_config)
    region_config["region"] = region_name
    region_config["retry_strategy"] = oci.retry.DEFAULT_RETRY_STRATEGY

    search_client = ResourceSearchClient(
        region_config,
        signer=signer,
        retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY,
    )
    network_client = VirtualNetworkClient(
        region_config,
        signer=signer,
        retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY,
    )

    regional_files = {
        base: output_dir / f"{base}-{tenancy_id}-{region_name}.jsonl" for base in RESOURCE_BASENAMES
    }
    for path in regional_files.values():
        path.write_text("", encoding="utf-8")

    counters = {base: 0 for base in RESOURCE_BASENAMES}
    skipped_404 = 0

    try:
        nsgs = paginate_search_query(
            search_client,
            NSG_QUERY,
            limit,
            max_throttle_retries,
            backoff_base,
        )
        append_jsonl(regional_files["nsgdata"], nsgs)
        counters["nsgdata"] = len(nsgs)

        total_rules = 0
        total_nsg_vnics = 0
        for nsg in nsgs:
            nsg_id = nsg.get("identifier")
            if not nsg_id:
                continue

            rules = paginate_nsg_rules(
                network_client,
                nsg_id,
                region_name,
                limit,
                max_throttle_retries,
                backoff_base,
            )
            append_jsonl(regional_files["nsgrules"], rules)
            total_rules += len(rules)

            nsg_vnics = paginate_nsg_vnics(
                network_client,
                nsg_id,
                region_name,
                limit,
                max_throttle_retries,
                backoff_base,
            )
            append_jsonl(regional_files["nsgvnic"], nsg_vnics)
            total_nsg_vnics += len(nsg_vnics)

        counters["nsgrules"] = total_rules
        counters["nsgvnic"] = total_nsg_vnics

        securitylists = paginate_search_query(
            search_client,
            SECURITYLIST_QUERY,
            limit,
            max_throttle_retries,
            backoff_base,
        )
        append_jsonl(regional_files["securitylists"], securitylists)
        counters["securitylists"] = len(securitylists)

        subnets = paginate_search_query(
            search_client,
            SUBNET_QUERY,
            limit,
            max_throttle_retries,
            backoff_base,
        )
        append_jsonl(regional_files["subnets"], subnets)
        counters["subnets"] = len(subnets)

        vnics = paginate_search_query(
            search_client,
            VNIC_QUERY,
            limit,
            max_throttle_retries,
            backoff_base,
        )
        append_jsonl(regional_files["vnics"], vnics)
        counters["vnics"] = len(vnics)

        routes = paginate_search_query(
            search_client,
            ROUTES_QUERY,
            limit,
            max_throttle_retries,
            backoff_base,
        )
        append_jsonl(regional_files["routes"], routes)
        counters["routes"] = len(routes)

        public_ip_ids = paginate_search_identifiers(
            search_client,
            PUBLICIP_QUERY,
            limit,
            max_throttle_retries,
            backoff_base,
        )
        public_ips, skipped_public_404 = fetch_public_ip_details(
            network_client,
            public_ip_ids,
            region_name,
            max_throttle_retries,
            backoff_base,
        )
        skipped_404 += skipped_public_404
        append_jsonl(regional_files["publicips"], public_ips)
        counters["publicips"] = len(public_ips)

        private_ips, skipped_private_404 = fetch_private_ips_by_subnets(
            network_client,
            subnets,
            region_name,
            limit,
            max_throttle_retries,
            backoff_base,
        )
        skipped_404 += skipped_private_404
        append_jsonl(regional_files["privateips"], private_ips)
        counters["privateips"] = len(private_ips)

        return region_name, counters, skipped_404, None
    except Exception as exc:  # noqa: BLE001
        return region_name, counters, skipped_404, str(exc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export OCI network resources to JSONL in one run (parallel by region)."
    )
    parser.add_argument("--tenancy-id", default="", help="Target tenancy OCID. Default: use config tenancy.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--config-file", default="~/.oci/config")
    parser.add_argument("--profile", default="DEFAULT")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--skip-region", default=DEFAULT_SKIP_REGION)
    parser.add_argument("--regions", default="", help="Optional CSV list of regions to include.")
    parser.add_argument("--workers", type=int, default=8, help="Max parallel region workers.")
    parser.add_argument("--max-throttle-retries", type=int, default=6)
    parser.add_argument("--backoff-base", type=float, default=1.0)
    parser.add_argument(
        "--keep-regional-files",
        action="store_true",
        default=False,
        help="Keep per-region intermediate files after generating consolidated JSONL files.",
    )

    parser.add_argument("-ip", action="store_true", default=False, dest="is_instance_principals")
    parser.add_argument("-dt", action="store_true", default=False, dest="is_delegation_token")
    parser.add_argument("-st", action="store_true", default=False, dest="is_security_token")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    config_file = str(Path(args.config_file).expanduser())
    config, signer = create_signer(
        config_file=config_file,
        profile=args.profile,
        is_instance_principals=args.is_instance_principals,
        is_delegation_token=args.is_delegation_token,
        is_security_token=args.is_security_token,
    )
    config["retry_strategy"] = oci.retry.DEFAULT_RETRY_STRATEGY

    tenancy_id = args.tenancy_id or config.get("tenancy")
    if not tenancy_id:
        raise RuntimeError("Unable to determine tenancy OCID. Provide --tenancy-id.")

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    identity_client = IdentityClient(
        config,
        signer=signer,
        retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY,
    )

    regions = [r.region_name for r in identity_client.list_region_subscriptions(tenancy_id).data]

    selected_regions = {r.strip() for r in args.regions.split(",") if r.strip()}
    if selected_regions:
        regions = [r for r in regions if r in selected_regions]

    if args.skip_region:
        regions = [r for r in regions if r != args.skip_region]

    if not regions:
        print("No regions selected. Nothing to do.")
        return

    workers = max(1, min(args.workers, len(regions)))
    print(f"Exporting all resources from {len(regions)} regions with {workers} workers...")

    total_counters = {base: 0 for base in RESOURCE_BASENAMES}
    total_skipped_404 = 0
    failures = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(
                export_region,
                region_name,
                config,
                signer,
                tenancy_id,
                args.limit,
                output_dir,
                args.max_throttle_retries,
                args.backoff_base,
            )
            for region_name in regions
        ]

        for future in concurrent.futures.as_completed(futures):
            region_name, counters, skipped_404, err = future.result()
            total_skipped_404 += skipped_404

            if err:
                failures.append((region_name, err))
                print(f"[ERROR] {region_name}: {err} (skipped404={skipped_404})")
                continue

            for base in RESOURCE_BASENAMES:
                total_counters[base] += counters.get(base, 0)

            print(
                "[OK] "
                f"{region_name}: "
                f"nsg={counters['nsgdata']}, rules={counters['nsgrules']}, nsgvnic={counters['nsgvnic']}, "
                f"securitylists={counters['securitylists']}, publicips={counters['publicips']}, "
                f"privateips={counters['privateips']}, subnets={counters['subnets']}, "
                f"vnics={counters['vnics']}, routes={counters['routes']}, skipped404={skipped_404}"
            )

    consolidate_outputs(
        output_dir=output_dir,
        tenancy_id=tenancy_id,
        regions=regions,
        keep_regional_files=args.keep_regional_files,
    )

    print(
        "Done. Consolidated files: "
        "nsgdata.jsonl, nsgrules.jsonl, nsgvnic.jsonl, securitylists.jsonl, "
        "publicips.jsonl, privateips.jsonl, subnets.jsonl, vnics.jsonl, routes.jsonl"
    )
    print(
        "Totals: "
        f"nsg={total_counters['nsgdata']}, rules={total_counters['nsgrules']}, nsgvnic={total_counters['nsgvnic']}, "
        f"securitylists={total_counters['securitylists']}, publicips={total_counters['publicips']}, "
        f"privateips={total_counters['privateips']}, subnets={total_counters['subnets']}, "
        f"vnics={total_counters['vnics']}, routes={total_counters['routes']}"
    )
    print(f"Skipped requests (404 NotAuthorizedOrNotFound): {total_skipped_404}")

    if failures:
        print(f"Regions with errors: {len(failures)}")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
