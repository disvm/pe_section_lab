# pe_section_lab

Mini lab Rust pour comprendre la table des sections d'un executable Windows PE.

Le programme prend un `.exe` en input, parcourt ses sections, compresse les donnees brutes avec zlib, vide les noms de sections et ajoute les flags READ/WRITE/EXECUTE.

```powershell
cargo run -- input.exe output.exe
```

Note: l'output est fait pour observer les headers et les sections, pas pour produire un vrai executable runnable. Un vrai packer aurait besoin d'un stub qui decompresse en memoire avant de sauter vers l'entrypoint original.
