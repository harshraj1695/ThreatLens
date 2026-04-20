# ⚙️ Full Setup Process (AF_PACKET INLINE)
### 🛠️ Step 1: Create veth pair (virtual cable)
```bash
sudo ip link add veth0 type veth peer name veth1
```
### 🛠️ Step 2: Bring interfaces up

```bash
sudo ip link set veth0 up
sudo ip link set veth1 up

```
### 🛠️ Step 3: Assign roles
Example:
veth0 → incoming traffic
veth1 → outgoing traffic


### 🛠️ Step 4: Run **Snort INLINE**
```bash
sudo snort \
  --daq afpacket \
  --daq-var inline=1 \
  --daq-var interfaces=veth0:veth1 \
  --daq-var use_mmap=1 \
  --daq-var buffer_size_mb=1024 \
  -c /usr/local/snort/etc/snort/snort.lua \
  -A alert_fast

```
### 🛠️ Step 5: Add DROP rule
Example:
```bash
drop tcp any any -> any 80 (msg:"Block HTTP"; sid:1001;)
```
👉 Now Snort will:

detect + block