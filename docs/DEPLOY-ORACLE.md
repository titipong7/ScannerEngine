# Deploy Scanner Engine บน Oracle Cloud (Ampere A1)

คู่มือนี้พาไปจาก "ยังไม่มีอะไรเลย" จนถึง "Vercel เรียก API ได้ผ่าน https"
ทุกคำสั่งรันบนเครื่อง Oracle ยกเว้นที่ระบุว่าเป็นในคอนโซล

สิ่งที่ต้องมีก่อน: บัญชี Oracle Cloud, โดเมน 1 ชื่อ (ใช้ subdomain เช่น
`scanner.yourdomain.com` ได้), และ Supabase project ที่รัน `supabase/schema.sql` แล้ว

---

## 1. สร้าง Instance

ในคอนโซล Oracle → **Compute → Instances → Create instance**

| ช่อง | ค่าที่เลือก |
|---|---|
| Image | Canonical Ubuntu 24.04 |
| Shape | **Ampere A1 Flex** — 4 OCPU / 24 GB (โควต้า Always Free ทั้งก้อน) |
| SSH key | อัปโหลด public key ของคุณ |
| Public IP | Assign |

**ถ้าเจอ `Out of host capacity`** — เป็นเรื่องปกติมากของ A1 ไม่ใช่ความผิดคุณ
ทางแก้เรียงตามความคุ้ม:

1. กด Create ซ้ำเรื่อยๆ ช่วงเวลาต่างกัน (มักว่างช่วงดึกตามเวลา region)
2. ลองสลับ Availability Domain (AD-1/2/3) ถ้า region คุณมีหลาย AD
3. ลดเป็น 2 OCPU / 12 GB — หาว่างง่ายกว่า และพอสำหรับ engine ตัวนี้สบายๆ
4. อัปเกรดบัญชีเป็น Pay-as-you-go (ยังใช้ Always Free ได้ฟรีเหมือนเดิม แต่ได้คิว
   จัดสรรทรัพยากรดีกว่าบัญชี Free trial)

จด **public IP** ไว้

## 2. เปิดพอร์ต (ต้องทำ 2 ที่ ไม่ใช่ที่เดียว)

จุดนี้คือที่คนพลาดกันมากที่สุด — Oracle มีไฟร์วอลล์ **สองชั้น** ต้องเปิดทั้งคู่

**ชั้นที่ 1 — VCN Security List** (ในคอนโซล)
Networking → Virtual Cloud Networks → VCN ของคุณ → Subnet → Security List →
Add Ingress Rules:

| Source CIDR | Protocol | Destination Port |
|---|---|---|
| `0.0.0.0/0` | TCP | 80 |
| `0.0.0.0/0` | TCP | 443 |

**ชั้นที่ 2 — iptables ในเครื่อง** — `deploy/bootstrap.sh` ในขั้นตอนที่ 4 ทำให้แล้ว

> อาการเวลาลืมชั้นใดชั้นหนึ่ง: `curl` จากข้างนอกค้างแล้ว timeout (ไม่ใช่
> connection refused) ถ้าเจอแบบนี้ให้กลับมาดูสองตารางนี้ก่อนอย่างอื่น

## 3. ชี้โดเมนมาที่เครื่อง

ที่ผู้ให้บริการ DNS ของคุณ เพิ่ม A record:

```
scanner.yourdomain.com.   A   <public IP ของ instance>
```

**ต้องทำก่อนขั้นตอนที่ 5** เพราะ Caddy ขอใบรับรองด้วยวิธี HTTP-01 ซึ่ง
Let's Encrypt จะยิงกลับมาที่โดเมนนี้ ถ้ายังไม่ชี้มา การขอใบรับรองจะล้มเหลว

รอให้ propagate แล้วเช็กจากเครื่องไหนก็ได้:

```bash
dig +short scanner.yourdomain.com     # ต้องได้ IP ของ instance
```

## 4. ติดตั้งบนเครื่อง

```bash
ssh ubuntu@<public IP>

git clone https://github.com/titipong7/ScannerEngine.git
cd ScannerEngine
bash deploy/bootstrap.sh
newgrp docker          # หรือ logout/login ใหม่
```

`bootstrap.sh` จะ: ติดตั้ง Docker + Compose plugin, เปิดพอร์ต 80/443 ใน iptables
แล้ว save ให้อยู่ถาวร, และ **ตรวจว่า outbound DNS ใช้ได้จริง** (ทั้ง UDP และ TCP
port 53) — ถ้าข้อนี้ไม่ผ่าน ทุกการสแกนจะขึ้น `error` เลยต้องแก้ก่อน deploy

## 5. ตั้งค่าแล้ว deploy

```bash
cp .env.example .env
nano .env
```

ค่าที่ต้องกรอก:

```ini
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_KEY=<service-role key>
API_KEY=<สุ่มเอง: openssl rand -hex 32>
SCANNER_DOMAIN=scanner.yourdomain.com
ACME_EMAIL=you@example.com
```

> `SUPABASE_KEY` ใช้ **service-role key** เท่านั้น มันข้าม RLS ได้ จึงต้องอยู่บน
> เซิร์ฟเวอร์เท่านั้น ห้ามเอาไปใส่ในโค้ดฝั่งเบราว์เซอร์เด็ดขาด
>
> `API_KEY` ไม่ใช่ตัวเลือก — `deploy.sh` จะปฏิเสธการ deploy ถ้าเว้นว่าง เพราะ
> การเปิด scanner ให้ใครก็ยิงได้ แปลว่าคุณเปิดเครื่องมือยิง DNS ให้คนทั้งโลก

```bash
bash deploy/deploy.sh
```

สคริปต์จะ build, start, รอจน container รายงาน healthy, แล้วยิง
`https://<domain>/health` ทวนอีกที **ถ้า container ใหม่ไม่ healthy มันจะ
rollback กลับไป image เดิมให้อัตโนมัติ** — build พังไม่ควรทำให้ของที่รันอยู่ล่ม

## 6. ทดสอบ

```bash
curl https://scanner.yourdomain.com/health

curl -X POST https://scanner.yourdomain.com/scan/full \
  -H 'Content-Type: application/json' \
  -H "X-API-Key: $(grep '^API_KEY=' .env | cut -d= -f2)" \
  -d '{"domain":"cloudflare.com"}'
```

ควรได้ JSON พร้อมคะแนน ถ้าไม่มี header `X-API-Key` ต้องได้ `401`

ทดสอบให้ครบ ควรยิงชุดของ badssl.com ด้วย เพราะเป็นชุดเดียวที่ทดสอบ TLS ได้จริง
(ในแซนด์บ็อกซ์ที่ผมพัฒนา TLS ถูก proxy คั่นกลางไว้ ทดสอบกับเว็บจริงไม่ได้):

```bash
for host in expired.badssl.com self-signed.badssl.com wrong.host.badssl.com; do
  curl -s -X POST https://scanner.yourdomain.com/scan/tls \
    -H 'Content-Type: application/json' -H "X-API-Key: $API_KEY" \
    -d "{\"domain\":\"$host\"}" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["domain"],d["status"],d["summary"])'
done
```

ทั้งสามต้องได้ `fail` พร้อมเหตุผลที่ต่างกัน

## 7. ต่อกับ Vercel

ในโปรเจกต์ Vercel → Settings → Environment Variables:

| Key | Value |
|---|---|
| `SCANNER_URL` | `https://scanner.yourdomain.com` |
| `SCANNER_API_KEY` | ค่าเดียวกับ `API_KEY` ใน `.env` |
| `SCANNER_TIMEOUT` | `45` |

ทั้งสามตัวเป็นฝั่งเซิร์ฟเวอร์ **ห้ามใส่ `NEXT_PUBLIC_` นำหน้า** ไม่งั้น API key
จะติดไปกับ JavaScript ที่ส่งให้ทุกคนที่เปิดเว็บ

Root Directory ของโปรเจกต์ตั้งเป็น `web`

จากนั้นแคบ CORS ของ engine จาก `*` เหลือเฉพาะ origin ของ Vercel — แก้ใน
`main.py` ที่ `allow_origins` แล้ว deploy ใหม่

## 8. งานดูแลหลังจากนี้

```bash
# ดู log
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f scanner-engine
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f caddy

# อัปเดตเป็นโค้ดล่าสุด
bash deploy/deploy.sh

# หยุด / เริ่มใหม่
docker compose -f docker-compose.yml -f docker-compose.prod.yml down
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

**ใบรับรอง TLS ต่ออายุเอง** Caddy จัดการให้ทั้งหมด เก็บไว้ใน volume `caddy-data`
— อย่าลบ volume นี้ ไม่งั้นต้องขอใหม่และอาจชน rate limit ของ Let's Encrypt

**Oracle ยึดเครื่องที่ idle** บัญชี Always Free ถ้าเครื่องใช้ CPU ต่ำกว่า 20%
และ network ต่ำ ติดต่อกัน 7 วัน อาจโดน reclaim ทางกันคือมี traffic สม่ำเสมอ
(ตั้ง uptime monitor ยิง `/health` ทุก 5 นาที ก็พอ) หรืออัปเป็น Pay-as-you-go

---

## ปัญหาที่เจอบ่อย

| อาการ | สาเหตุที่น่าจะเป็น | วิธีเช็ก |
|---|---|---|
| `curl` จากข้างนอก timeout | ลืมเปิดพอร์ตชั้นใดชั้นหนึ่ง | `sudo iptables -L INPUT -n --line-numbers` และดู VCN Security List |
| Caddy ขอใบรับรองไม่สำเร็จ | DNS ยังไม่ชี้มา / พอร์ต 80 ปิด | `docker compose ... logs caddy`, `dig +short <domain>` |
| ทุกการสแกนได้ `error` | outbound port 53 ถูกบล็อก | `dig @1.1.1.1 example.com`, `dig +tcp @1.1.1.1 TXT github.com` |
| SPF/DKIM timeout แต่ DNSSEC ผ่าน | TCP 53 ถูกบล็อก (คำตอบ TXT ใหญ่เกิน UDP) | `dig +tcp @1.1.1.1 TXT github.com` |
| `persisted: false` ทุกครั้ง | Supabase key ผิด หรือ schema ยังไม่ได้รัน | `docker compose ... logs scanner-engine \| grep -i supabase` |
| `401` ทั้งที่ส่ง key แล้ว | `API_KEY` ใน `.env` กับที่ Vercel ไม่ตรงกัน | เทียบสองค่า แล้ว `deploy.sh` ใหม่ |
| ดิสก์เต็ม | image เก่าค้าง | `docker system prune -a` (`deploy.sh` prune ให้อยู่แล้วทุกครั้ง) |

## ถ้ายังไม่มีโดเมน

Let's Encrypt ออกใบรับรองให้ IP เปล่าๆ ไม่ได้ ทางเลือกเรียงตามที่ผมแนะนำ:

1. **จดโดเมนสักชื่อ** (~300–400 บาท/ปี) — ตรงไปตรงมาที่สุด และคุณต้องมีอยู่ดี
   ถ้าจะเปิดให้คนอื่นใช้
2. **ใช้ subdomain ฟรี** เช่น DuckDNS — ใช้ได้จริงกับ Let's Encrypt
3. **ยิงตรงที่ IP แบบไม่มี TLS** — พอทดสอบภายในได้ แต่ **ห้ามใช้กับ Vercel**
   เพราะ API key จะวิ่งข้ามอินเทอร์เน็ตแบบไม่เข้ารหัส และเว็บ https จะเรียก
   origin http ไม่ได้อยู่ดี
