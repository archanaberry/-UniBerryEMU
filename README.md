# 🍓 UniBerryEMU

**UniBerryEMU** adalah mesin *emulation & lightweight userspace virtualization* eksperimental yang berfokus pada **emulasi flat binary lintas OS/ABI** dengan pendekatan *temporary executable wrapping* (Temp-ELF / Temp-PE / Temp-MachO) dan eksekusi melalui **Unicorn Engine**.

Proyek ini adalah fondasi dari ekosistem **UBerryNix** dan ditujukan untuk riset, edukasi, serta eksperimen tingkat rendah (*low-level system & binary engineering*).

![Archana Berry ELF - Edition](archanaberry/berryelf.png)

---

## ✨ Fitur Utama

* 🧠 **Flat Binary Emulation**
  Menjalankan *raw / flat binary* tanpa header formal dengan membungkusnya menjadi format sementara (Temp-ELF, Temp-PE, Temp-MachO).

* 🔌 **Multi Binary Format Parsing**
  Mendukung parsing awal untuk:

  * ELF (Linux)
  * PE / MZ (Windows)
  * Mach-O (macOS)

* 🦄 **Powered by Unicorn Engine**
  Eksekusi CPU-level berbasis emulasi instruksi (x86, x86_64, ARM, AArch64 – bertahap).

* 🌱 **Header-less Execution Concept**
  Fokus pada *code section execution*, bukan loader kernel penuh.

* 🧪 **Experimental & Modular**
  Dirancang modular agar mudah dikembangkan menjadi:

  * Nano-kernel emulator
  * Userspace VM
  * Hybrid chroot / proot-like environment

---

## 🧩 Arsitektur Singkat

```
[ Flat Binary ]
      ↓
[ Binary Parser ]  (ELF / PE / Mach-O)
      ↓
[ Temp Executable Wrapper ]
      ↓
[ Unicorn Engine ]
      ↓
[ Virtual CPU + Memory ]
```

UniBerryEMU **tidak bertindak sebagai OS penuh**, melainkan sebagai *execution container* untuk kode mesin.

---

## 📦 Komponen Utama

* **UniBerryEMU Core**
  Mesin emulasi utama (Unicorn wrapper).

* **Binary Loader Layer**
  Parser format biner (ELF / PE / Mach-O).

* **Temp Executable Generator**
  Membuat representasi executable minimal tanpa header kernel standar.

* **Memory Mapper**
  Mengatur stack, heap, dan entry point virtual.

---

## 🛠️ Build & Dependensi

### Dependensi

* `unicorn-engine`
* `gcc` atau `clang`
* `make`
* `libc` (glibc / musl)

### Build Dasar (contoh)

```bash
git clone https://github.com/archanaberry/-UniBerryEMU.git
cd -UniBerryEMU
make
```

> ⚠️ Catatan: Proyek ini masih *early stage*, struktur build bisa berubah.

---

## ▶️ Cara Pakai (Konsep Awal)

```bash
uniberryemu input.bin
```

Atau untuk format spesifik:

```bash
uniberryemu --elf test.flat
uniberryemu --pe shellcode.bin
```

---

## 🧠 Filosofi Desain

* **Lebih dekat ke CPU daripada OS**
* **Tidak mengandalkan kernel host**
* **Eksperimen bebas tanpa ABI ketat**
* **Ringan, fleksibel, dan transparan**

UniBerryEMU **bukan QEMU replacement**, melainkan *research-oriented execution engine*.

---

## 🔬 Status Proyek

* 🚧 Sangat Eksperimental
* 🧪 Fokus riset & pembelajaran
* ❌ Belum aman untuk produksi

---

## 🗺️ Roadmap (Rencana)

* [ ] Flat binary loader stabil
* [ ] ELF / PE / Mach-O parser lebih lengkap
* [ ] Syscall emulation minimal
* [ ] Memory protection layer
* [ ] CLI debugger sederhana
* [ ] Integrasi UniBerryNix

---

## 🤝 Kontribusi

Kontribusi sangat terbuka:

* Diskusi konsep
* Penulisan kode
* Dokumentasi
* Reverse engineering

Silakan buka **Issue** atau **Pull Request**.

---

## 📜 Lisensi

Proyek ini mengikuti lisensi **AB-BSD2**..

---

## 🍓 Catatan Akhir

UniBerryEMU adalah eksperimen tentang **"bagaimana jika binary bisa berjalan tanpa OS"**.

Jika kamu tertarik dengan:

* emulator
* virtual machine
* kernel minimal
* binary format

maka proyek ini untukmu.

---

**Made with curiosity & berries 🍓**
