# ctfd-solver — solver universal CTFd (lomba jeorpadic online)

Login ke platform CTFd lewat API, list challenge, unduh attachment, submit
flag, autosolve misc (rantai decode via `../ctf-decoder`), sweep massal dari
`flags.json`. Stdlib-only, retry otomatis kalau server 500 sesaat.

## Setup (sekali)

```bash
git clone https://github.com/bryanleeanito/Ptoolsdexeroid.git
cd Ptoolsdexeroid/kits/ctfd-solver
export CTF_URL=https://ctf.smkpgri3malang.web.id
export CTF_USER=leeanito          # ganti username kamu
read -s CTF_PASS && export CTF_PASS   # password via env, TIDAK di file repo
```

## Pemakaian

```bash
python3 ctfd.py status              # whoami + posisi scoreboard
python3 ctfd.py list                # semua challenge + centang solved
python3 ctfd.py fetch --all         # unduh semua attachment ke files/
python3 ctfd.py submit 12 "flag{...}"
python3 ctfd.py sweep flags.json    # submit massal (skip yang sudah solved)
python3 ctfd.py autosolve           # decode otomatis challenge misc/encoding
```

## flags.json

```json
[
  {"id": 3, "flag": "flag{darihasilkamu}"},
  {"id": 7, "flag": "flag{hasil_decode}"}
]
```

Isi manual dari hasil solve, atau `autosolve` yang mengisi otomatis untuk
soal misc berbasis encoding (soal web/rev tetap manual / kit lain).

## Keamanan

- Password HANYA dari env `CTF_PASS` / `CTF_PASS_FILE` / prompt — tidak
  pernah ditulis ke file yang di-commit.
- Cookie session di `.cookies` sudah masuk `.gitignore`.
- Kredensial di repo manapun = diskualifikasi. Serius.

## Troubleshooting

- `GET /login = HTTP 500` → server CTF lagi rusak (template/route), bukan
  salah kamu. Uji dari browser; kalau sama, lapor panitia.
- Token API ditolak (403) → admin menonaktifkan API token; otomatis fallback
  form login.
- Submit `incorrect` → flag salah / sudah keburu ketemu orang lain (kalau
  dynamic flag beda per akun, ambil dari target langsung).
