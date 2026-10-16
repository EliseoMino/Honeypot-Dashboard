import type { ReactNode } from "react";

interface IpCountryProps {
  countryCode?: string | null;
  countryName?: string | null;
}

/** Render approximate local GeoIP country context; never imply exact location. */
export function IpCountry({ countryCode, countryName }: IpCountryProps): ReactNode {
  if (!countryCode || !/^[A-Z]{2}$/.test(countryCode)) return null;
  const flag = String.fromCodePoint(
    ...[...countryCode].map((letter) => 0x1f1e6 + letter.charCodeAt(0) - 65),
  );
  const label = countryName ?? countryCode;
  return (
    <span className="ip-country" title={`País aproximado por MaxMind GeoLite2: ${label}`}>
      <span role="img" aria-label={label}>{flag}</span>
      <span>{label}</span>
    </span>
  );
}
