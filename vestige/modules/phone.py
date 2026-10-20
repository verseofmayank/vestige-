"""Phone number metadata via the `phonenumbers` library (offline numbering-plan data).

Everything except the optional NumVerify call is computed locally. No identification of
individuals, no address discovery.
"""
from __future__ import annotations

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder, timezone

from vestige.core.context import Batch, Context
from vestige.core.http_client import ProviderError
from vestige.core.models import Confidence, Observation, SourceResult, Status, utcnow
from vestige.core.scope import ValidationError

NUMVERIFY_URL = "https://apilayer.net/api/validate"  # HTTPS only; never http://

_TYPE_NAMES = {
    PhoneNumberType.FIXED_LINE: "fixed line", PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed line or mobile", PhoneNumberType.TOLL_FREE: "toll free",
    PhoneNumberType.PREMIUM_RATE: "premium rate", PhoneNumberType.SHARED_COST: "shared cost",
    PhoneNumberType.VOIP: "VoIP", PhoneNumberType.PERSONAL_NUMBER: "personal number",
    PhoneNumberType.PAGER: "pager", PhoneNumberType.UAN: "universal access number",
    PhoneNumberType.VOICEMAIL: "voicemail", PhoneNumberType.UNKNOWN: "unknown",
}


_REASONS = {int(v): k for k, v in vars(phonenumbers.ValidationResult).items() if k.isupper() and isinstance(v, int)}


def parse_number(raw: str, default_region: str | None = None) -> phonenumbers.PhoneNumber:
    if not raw or not raw.strip():
        raise ValidationError("phone number is empty")
    text = raw.strip()
    if not text.lstrip("( ").startswith("+") and not default_region:
        raise ValidationError("phone number must start with '+' and a country code (e.g. +919876543210), or pass --region IN")
    try:
        return phonenumbers.parse(text, default_region.upper() if default_region else None)
    except phonenumbers.NumberParseException as exc:
        raise ValidationError(f"cannot parse phone number: {exc}") from exc


def describe(num: phonenumbers.PhoneNumber) -> dict:
    valid = phonenumbers.is_valid_number(num)
    possible = phonenumbers.is_possible_number(num)
    reason = phonenumbers.is_possible_number_with_reason(num)
    ntype = phonenumbers.number_type(num)
    region = phonenumbers.region_code_for_number(num)
    return {
        "e164": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL),
        "country_code": num.country_code,
        "region": region,
        "is_possible": possible,
        "is_valid": valid,
        "possibility_reason": _REASONS.get(int(reason), str(reason)),
        "number_type": _TYPE_NAMES.get(ntype, "unknown") if valid else "n/a (number not valid)",
        "number_type_note": "derived from numbering-plan prefixes; a mobile prefix does not prove the line is active",
        "geographic_area": (geocoder.description_for_number(num, "en") or None) if valid else None,
        "geographic_note": "area of the numbering-plan allocation, NOT the current location of the subscriber",
        "carrier_original_allocation": (carrier.name_for_number(num, "en") or None) if valid else None,
        "carrier_note": "original allocation from numbering-plan data; ignores number portability; not live carrier verification",
        "timezones": list(timezone.time_zones_for_number(num)) if valid else [],
    }


def parse_numverify(doc: dict) -> dict:
    if not isinstance(doc, dict):
        raise ProviderError("malformed", "NumVerify response is not an object")
    if doc.get("success") is False or "error" in doc:
        err = doc.get("error") or {}
        code = err.get("code")
        kind = "auth" if code in (101, 102, 103) else "ratelimit" if code in (104, 106) else "http"
        raise ProviderError(kind, f"NumVerify error {code}: {err.get('info', 'unknown')}")
    return {"valid": doc.get("valid"), "carrier": doc.get("carrier") or None, "line_type": doc.get("line_type") or None,
            "country_name": doc.get("country_name"), "location": doc.get("location") or None}


def numverify(ctx: Context, e164: str) -> Batch:
    res = ctx.http.get(NUMVERIFY_URL, params={"access_key": ctx.creds["NUMVERIFY_KEY"], "number": e164.lstrip("+")},
                       source="numverify", ok=(200,))
    info = parse_numverify(res.json())
    info["note"] = "provider-reported data; accuracy and freshness depend on the provider"
    return Batch([Observation("phone_provider_lookup", e164, "numverify", Confidence.MEDIUM, utcnow(), info)],
                 http_status=res.status)


def phone_recon(ctx: Context, raw: str, *, region: str | None = None, provider: bool = True) -> dict:
    num = parse_number(raw, region)
    info = describe(num)
    now = utcnow()
    conf = Confidence.HIGH if info["is_valid"] else Confidence.MEDIUM
    ctx.inv.observations.append(Observation("phone_metadata", info["e164"], "phonenumbers (offline library)", conf, now, info))
    ctx.record(SourceResult("phone", "phonenumbers (offline)", Status.OK,
                                    "valid number" if info["is_valid"] else f"not a valid number ({info['possibility_reason']})",
                                    items=1))
    if provider:
        ctx.run_source("phone", "numverify", lambda: numverify(ctx, info["e164"]), requires="NUMVERIFY_KEY",
                       skip_reason=None if info["is_valid"] else "number is not valid; external lookup skipped")
    ctx.inv.limitations.append("Carrier and region come from numbering-plan allocation data, not a live network query.")
    return info
