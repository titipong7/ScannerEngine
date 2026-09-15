# Web Audit Platform — Roadmap (MVP)

แผนพัฒนา 4 สัปดาห์สำหรับ MVP บนสถาปัตยกรรมที่ไม่มีค่าใช้จ่ายรายเดือน
สถานะอัปเดตล่าสุด: 2026-09-15

## สถาปัตยกรรมภาพรวม

```
ผู้ใช้ ──▶ Vercel (Next.js Dashboard)
             │  1. POST /scan/*  (พร้อม X-API-Key)
             ▼
        Oracle Cloud Ampere A1 (ARM64)
        Caddy (TLS) ──▶ Docker: Scanner Engine (FastAPI)
             │  2. insert ผลสแกน
             ▼
        Supabase (PostgreSQL + Auth + RLS)
             ▲
             └── 3. Dashboard อ่านผลลัพธ์/ประวัติกลับไปแสดง
```

จุดสำคัญ: **Dashboard ไม่ได้อ่านผลจาก response ของ Scanner โดยตรงเท่านั้น**
แต่ให้ Scanner เขียนลง Supabase แล้ว Dashboard อ่านจาก Supabase — ทำให้ได้ประวัติ
การสแกนย้อนหลังฟรี และหน้าเว็บยังใช้งานได้แม้ Scanner จะล่ม

| ส่วนประกอบ | บริการ | ค่าใช้จ่าย |
|---|---|---|
| Scanner Engine | Oracle Cloud Always Free (Ampere A1, 4 OCPU / 24 GB) | 0 |
| Database + Auth | Supabase Free tier | 0 |
| Frontend | Vercel Hobby | 0 |
| Domain + TLS | โดเมนที่มีอยู่ + Let's Encrypt ผ่าน Caddy | ค่าโดเมนรายปี |

---

## สัปดาห์ที่ 1 — Server และ Infrastructure

**สถานะ: ยังไม่เริ่ม (รอ provision เครื่องจริง)**

- [ ] สมัคร Oracle Cloud และสร้าง Instance แบบ Always Free
      — เลือก **Ampere A1 (ARM64)**, Ubuntu 24.04, 4 OCPU / 24 GB
      — ถ้า region เต็มจนสร้างไม่ได้ (เจอ `Out of host capacity` บ่อยมาก)
        ให้ลองสร้างซ้ำเป็นรอบ ๆ หรือย้าย home region
- [ ] ตั้งค่า Network / Security
      — VCN Security List: เปิด ingress TCP 22, 80, 443
      — **ห้ามลืม iptables ในเครื่อง** Oracle ตั้ง DROP ไว้เป็นค่าเริ่มต้น:
        ```bash
        sudo iptables -I INPUT 1 -p tcp --dport 80  -j ACCEPT
        sudo iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
        sudo netfilter-persistent save
        ```
      — ตรวจว่า **outbound UDP/TCP 53 ออกได้** ไม่งั้นทุกการสแกนจะ timeout
      — ไม่ต้องเปิด 8000 ออกสู่อินเทอร์เน็ต ให้ Caddy proxy เข้ามาแทน
- [ ] ติดตั้ง Docker + Compose plugin
      ```bash
      sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin
      sudo usermod -aG docker "$USER" && newgrp docker
      ```
- [ ] วาง Caddy หน้าเป็น reverse proxy เพื่อรับ TLS อัตโนมัติ
      (`scanner.<โดเมนของคุณ> { reverse_proxy scanner-engine:8000 }`)
- [ ] ตั้ง `API_KEY` ใน `.env` เพื่อไม่ให้ใครก็ได้ยิง Scanner ของเรา
- [ ] GitOps: ตั้ง deploy ด้วย `git pull && docker compose up -d --build`
      (ยกระดับเป็น GitHub Actions + self-hosted runner ทีหลังได้)

**เกณฑ์ผ่าน:** `curl https://scanner.<domain>/health` ได้ `{"status":"ok"}` จากเครื่องนอก

---

## สัปดาห์ที่ 2 — Scanner Engine / Worker

**สถานะ: เสร็จแล้วเป็นส่วนใหญ่** (branch `claude/scanner-engine-web-audit-gu6fzz`)

- [x] `POST /scan/dns` — ตรวจ DNSSEC เต็มห่วงโซ่ความเชื่อถือ
      DS ที่ parent zone → DNSKEY ที่ apex → RRSIG ที่ตรวจสอบลายเซ็นผ่านจริง
      และยังไม่หมดอายุ → DS digest ตรงกับ key ที่ประกาศ → AD flag จาก resolver
      (โซนที่เซ็นแล้วแต่พัง จะรายงานเป็น `fail` พร้อมสาเหตุ ไม่ปนกับ "ไม่ได้เปิด")
- [x] `POST /scan/email` — SPF + DMARC พร้อมให้เกรด ไม่ใช่แค่เช็กว่ามี/ไม่มี
      (SPF ซ้ำซ้อน, `+all`/`?all`, เพดาน 10 DNS lookup, `p=`, `pct`, `rua`, `sp`)
- [x] จัดการ error: NXDOMAIN / timeout / SERVFAIL แปลงเป็น response ที่อ่านรู้เรื่อง
      ไม่ใช่ 500
- [x] Containerize สำหรับ ARM64 (two-stage build, non-root, healthcheck)
- [x] Unit test แบบออฟไลน์ + `/health` probe
- [ ] **DKIM** — ต้องรู้ selector ก่อน จึงควรให้ผู้ใช้กรอก selector เอง
      (หรือลองเดาจากชุดยอดนิยม: `google`, `selector1`, `selector2`, `k1`, `dkim`)
- [ ] **SSL/TLS scan** — วันหมดอายุใบรับรอง, chain ครบไหม, TLS version,
      cipher ที่อ่อน, HSTS (ใช้ `ssl` + `socket` ของ Python ไม่ต้องพึ่ง binary ภายนอก)
- [ ] **Scoring** — รวมผลทุกโมดูลเป็นคะแนน 0–100 + เกรด A–F (ดูสัปดาห์ที่ 3)
- [ ] Rate limiting ต่อ IP (กัน abuse ตอนเปิดสาธารณะ)
- [ ] ถ้าจำนวนงานเริ่มเยอะค่อยเติม queue (Redis + arq) — ตอนนี้ยังไม่จำเป็น
      เพราะสแกน 1 ครั้งใช้เวลาไม่ถึง 2 วินาที

**หมายเหตุ:** สเปกเดิมเขียนว่าใช้คำสั่ง `dig` — โค้ดจริงใช้ `dnspython` แทน
เพราะไม่ต้อง spawn subprocess, ไม่ต้อง parse ข้อความเอาต์พุต, และตรวจลายเซ็น
DNSSEC ด้วย `dns.dnssec.validate()` ได้จริง ซึ่ง `dig` ทำแทนไม่ได้

---

## สัปดาห์ที่ 3 — Database

**สถานะ: มีตาราง `scan_results` แล้ว (`supabase/schema.sql`) ที่เหลือรอขยาย**

- [x] ตาราง `scan_results` (domain, scan_type, status, summary, findings, raw_data, created_at)
- [x] เชื่อม Scanner → Supabase ด้วย service-role key (เขียนแบบ best effort:
      ถ้า Supabase ล่ม การสแกนยังคืนผลได้ แค่ `persisted: false`)
- [ ] ขยาย schema ให้รองรับผู้ใช้และประวัติ:

  | ตาราง | ใช้ทำอะไร |
  |---|---|
  | `profiles` | ผูกกับ `auth.users` ของ Supabase เก็บ plan/โควต้า |
  | `domains` | โดเมนที่ผู้ใช้เฝ้าดู (`user_id`, `domain`, `verified_at`) |
  | `scans` | 1 แถว = 1 ครั้งที่กดสแกน (ร้อยหลาย `scan_results` เข้าด้วยกัน) |
  | `scan_results` | ผลดิบรายโมดูล (มีอยู่แล้ว เพิ่ม `scan_id` FK) |
  | `scores` | คะแนนรวมต่อครั้ง เอาไว้พล็อตกราฟย้อนหลัง |

- [ ] **RLS policy** — จุดนี้พลาดง่ายและอันตรายที่สุด:
      เปิด RLS ทุกตาราง, ให้ผู้ใช้อ่านได้เฉพาะแถวที่ `user_id = auth.uid()`,
      ส่วน Scanner ใช้ service-role key ซึ่ง bypass RLS อยู่แล้ว
      **service-role key ต้องอยู่บนเซิร์ฟเวอร์เท่านั้น ห้ามหลุดไปฝั่ง browser เด็ดขาด**
- [ ] สูตรคะแนน (เสนอเป็นจุดตั้งต้น):
      DNSSEC 30 + SPF 20 + DMARC 25 + DKIM 10 + TLS 15 = 100
      โดย `pass` = เต็ม, `warn` = ครึ่ง, `fail`/`error` = 0
- [ ] ตั้ง retention / cron ลบ `raw_data` เก่ากว่า 90 วัน (Supabase free tier 500 MB)

---

## สัปดาห์ที่ 4 — Dashboard

**สถานะ: ยังไม่เริ่ม**

- [ ] Next.js (App Router) + Tailwind — หน้าแรกมีช่องกรอกโดเมนช่องเดียว
- [ ] Flow การสแกน: หน้าเว็บเรียก Route Handler ของตัวเอง → Route Handler
      เรียก Scanner ด้วย `API_KEY` ฝั่งเซิร์ฟเวอร์ → อ่านผลจาก Supabase มาแสดง
      (**ห้ามให้ browser ยิง Scanner ตรง ๆ** เพราะจะต้องเปิด API key ให้เห็น)
- [ ] หน้าแสดงผล: คะแนนรวมเป็นวงกลม, การ์ดแยกตามโมดูล, รายการ `findings`
      พร้อมคำแนะนำวิธีแก้, และปุ่มกางดู `raw_data` สำหรับคนที่อยากดูละเอียด
- [ ] Supabase Auth (magic link) + หน้าประวัติการสแกนของโดเมนที่บันทึกไว้
- [ ] Deploy บน Vercel ผูกกับ Git repo ให้ auto deploy ทุก push
- [ ] ตั้ง CORS ของ Scanner ให้เหลือเฉพาะ origin ของ Vercel
      (ตอนนี้เปิด `*` ไว้เพื่อความสะดวกตอนพัฒนา)

---

## ลำดับงานที่แนะนำถัดไป

1. **สัปดาห์ที่ 1 (infra)** — เพราะ Scanner พร้อมแล้ว แต่ยังไม่มีที่ให้รันจริง
   และการหา Ampere A1 ว่างอาจใช้เวลาหลายวัน ควรเริ่มไว้แต่เนิ่น ๆ
2. **SSL/TLS module** — เป็นสิ่งที่ผู้ใช้ทั่วไปเข้าใจง่ายที่สุด ("ใบรับรองจะหมดอายุ
   ในอีก 12 วัน") และเพิ่มคุณค่าให้ผลสแกนทันที
3. **Scoring + schema ขยาย** — ต้องมีคะแนนก่อน หน้า Dashboard ถึงจะมีอะไรให้โชว์
4. **Dashboard** — ทำทีหลังสุด เพราะต้องรู้หน้าตาข้อมูลที่แน่นอนแล้ว
5. DKIM ทำเป็นลำดับท้าย เพราะต้องออกแบบ UX เรื่อง selector เพิ่ม

## ความเสี่ยงที่ควรรู้ล่วงหน้า

| ความเสี่ยง | ผลกระทบ | วิธีรับมือ |
|---|---|---|
| Oracle A1 หาไม่ได้ (`Out of host capacity`) | สัปดาห์ที่ 1 ยืดออกไป | ลองสร้างซ้ำเป็นรอบ / เปลี่ยน AD / สำรองด้วย VM x86 ชั่วคราว |
| Oracle reclaim เครื่อง Always Free ที่ idle | เครื่องหาย | ให้มี traffic สม่ำเสมอ (health check จากภายนอก) + ผูกบัตรเป็น Pay-as-you-go ที่ยังใช้ฟรี |
| Outbound 53 ถูกบล็อก | ทุกการสแกนเป็น `error` | ทดสอบด้วย `dig @1.1.1.1` ตั้งแต่วันแรกที่ได้เครื่อง |
| ถูกใช้ยิง DNS abuse | ถูกบล็อก / ค่าใช้จ่าย | `API_KEY` + rate limit ต่อ IP + แคชผลรายโดเมนสัก 5 นาที |
| service-role key หลุด | ใครก็แก้ฐานข้อมูลได้ | เก็บฝั่งเซิร์ฟเวอร์เท่านั้น + เปิด RLS ทุกตาราง |
