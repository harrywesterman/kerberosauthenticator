# SMB GSS-diagnoseontwerp

## Doel

De onderliggende GSS/Kerberos-status van een mislukte SMB-aanmelding veilig zichtbaar maken, zodat
de DFS-namespace-aanmelding gericht kan worden hersteld.

## Besluit

Bij een mislukte SMB-aanmelding doorzoekt `KerberosSmbClient` de oorzaakketen naar een
`GSSException`. Alleen de numerieke GSS major- en minor-status worden aan de bestaande,
gebruikerszichtbare fouttekst toegevoegd. De oorspronkelijke exception blijft oorzaak voor
technische diagnose.

## Veiligheid

Geen exceptionbericht, gebruikersnaam, wachtwoord, ticket, sessiesleutel of SPNEGO-token wordt
getoond of gelogd. Er komt geen NTLM-, gast- of alternatieve-SPN-fallback.

## Validatie

Een unit-test dekt een geneste `GSSException` en een niet-GSS-fout. Na de lokale JDK-17-tests
wordt de gesigneerde release via GitHub Actions op het beheerde toestel getest. De getoonde
numerieke GSS-status bepaalt pas daarna de gerichte oplossing.
