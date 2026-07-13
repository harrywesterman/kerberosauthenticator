# Directe DFS-ondersteuning voor bedrijfsbestanden

## Doel

De bedrijfsbestanden-app moet een door MDM geconfigureerde DFS-namespace, zoals
`\\politie.local\np\Organisatie`, direct kunnen openen met Kerberos-only SMB.

## Context

De app gebruikt SMBJ 0.14.0. Die bibliotheek bevat een DFS-path resolver, maar DFS is standaard
uitgeschakeld. De huidige `SmbConfig` schakelt DFS niet in, waardoor referrals niet worden
gevolgd. De MDM-shareconfiguratie en de bestaande Kerberos-account blijven de bron van waarheid.

## Besluit

Schakel DFS in voor alle beheerde SMB-sessies via de SMBJ-configuratie.

SMBJ vraagt eerst een Kerberos-sessie voor de DFS-namespace op en volgt vervolgens de referral.
Wanneer de referral naar een andere server wijst, gebruikt SMBJ dezelfde GSS-authenticatiecontext
om daar opnieuw aan te melden. Daardoor vraagt de Kerberos-stack het passende
`cifs/<dfs-doelserver>`-ticket aan. De app voegt geen NTLM-, gast- of handmatige-SPN-fallback toe.

## Grenzen

- De MDM-configuratie blijft `host`, `share_name` en `start_path` gebruiken; er komt geen
  fysieke doelserver-override.
- SMB-signing en de optionele SMB3-encryptieverplichting blijven ongewijzigd.
- Fouten uit Kerberos of DFS worden niet verborgen door een alternatieve aanmeldmethode.

## Validatie

1. Een unit-test bewaakt dat de SMB-configuratie DFS-capability inschakelt, naast signing en de
   ondersteunde SMB-dialecten.
2. De relevante unit-tests en een JDK-17 releasebuild draaien lokaal.
3. De wijziging wordt op `main` gepubliceerd. De gesigneerde release-APK uit GitHub Actions wordt
   als in-place update op het beheerde toestel geïnstalleerd.
4. Met de Tunnel-VPN actief wordt de G-schijf geopend en wordt gecontroleerd dat de DFS-mapinhoud
   verschijnt, zonder gevoelige loggegevens vast te leggen.
