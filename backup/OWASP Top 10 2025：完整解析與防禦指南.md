<div align="center">

<img src="https://raw.githubusercontent.com/fenryx-tech/.github/main/profile/assets/logo/logo-128.png" alt="Fenryx Logo" width="128" height="128">


# OWASP Top 10 2025：完整解析與防禦指南

**以攻擊視角打造強韌系統**

</div>

[![Website](https://img.shields.io/badge/Website-fenryx.tech-D72638?style=flat-square)](https://fenryx.tech)
[![Email](https://img.shields.io/badge/Email-contact@fenryx.tech-D72638?style=flat-square)](mailto:contact@fenryx.tech)

</div>

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

**發布日期：** 2025-11-26  
**作者：** Fenryx 技術團隊  
**版本：** 1.0  
**參考來源：** https://owasp.org/Top10/2025/

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 文章資訊

- **目標關鍵字：** OWASP Top 10 2025, Web安全, 應用程式安全, OWASP, Web Application Security
- **目標讀者：** 開發者、資安人員、技術決策者、CTO、資安主管
- **預估閱讀時間：** 25-30 分鐘
- **難度等級：** 中級

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 1. 引言

### OWASP Top 10 是什麼？

OWASP（Open Web Application Security Project）是一個非營利組織，致力於改善軟體安全性。OWASP Top 10 是該組織每 3-4 年發布一次的報告，列出 Web 應用程式最常見的 10 種安全風險。

這份報告基於全球數千個應用程式的真實漏洞資料，是業界最權威的 Web 應用程式安全指南之一。

### 為什麼 2025 版本重要？

OWASP Top 10 2025 版本反映了當前 Web 應用程式安全的最新威脅趨勢。與 2021 版本相比，2025 版本：

- **反映新威脅** - 包含雲端安全、API 安全、供應鏈安全等新興威脅
- **更新資料** - 基於最新的漏洞統計資料
- **調整優先順序** - 根據實際影響調整漏洞排名

![OWASP Top 10 2025](https://owasp.org/Top10/assets/2025-mappings.png)

### 本文將涵蓋什麼？

本文將深入解析 OWASP Top 10 2025 的每個項目，包含：

- **詳細解析** - 每種漏洞的原理、影響與攻擊方式
- **實際案例** - 真實世界的攻擊案例與場景
- **防禦最佳實踐** - 具體的防禦措施與程式碼範例
- **實務建議** - 如何將防禦整合到開發流程

無論您是開發者、資安人員，還是技術決策者，這篇文章都將為您提供實用的 Web 應用程式安全知識。

> **Fenryx 觀點**  
> 我們相信，真正的安全來自於理解攻擊者的思維。透過攻擊者視角檢視系統，我們能找出傳統防禦方法容易忽略的弱點，並建立更強韌的防禦機制。

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 2. OWASP Top 10 2025 概述

### Top 10 2025 完整列表

根據 [OWASP Top 10 2025 官方文件](https://owasp.org/Top10/2025/0x00_2025-Introduction/)，以下是 Web 應用程式最常見的 10 種安全風險：

1. **A01:2025 – Broken Access Control（權限控制失效）**
2. **A02:2025 – Security Misconfiguration（安全設定錯誤）**
3. **A03:2025 – Software Supply Chain Failures（軟體供應鏈失敗）**
4. **A04:2025 – Cryptographic Failures（加密機制失效）**
5. **A05:2025 – Injection（注入攻擊）**
6. **A06:2025 – Insecure Design（不安全設計）**
7. **A07:2025 – Authentication Failures（身份驗證失敗）**
8. **A08:2025 – Software or Data Integrity Failures（軟體或資料完整性失敗）**
9. **A09:2025 – Logging & Alerting Failures（日誌與告警失敗）**
10. **A10:2025 – Mishandling of Exceptional Conditions（異常條件處理不當）**

> **重要說明：** OWASP Top 10 2025 版本對比 2021 版本有重大變化，包括新增項目（A03: Software Supply Chain Failures、A10: Mishandling of Exceptional Conditions）、項目順序調整，以及部分項目名稱更新。本文基於 2025 版本撰寫，參考來源：https://owasp.org/Top10/2025/

### 2025 版本的重要更新

2025 版本的內容已根據最新威脅趨勢進行了重要更新：

- **API 安全強化** - 所有項目都增加了針對 API 安全的最佳實踐和範例
- **雲端原生安全** - 增加了雲端環境（AWS、Azure、GCP）的安全考量
- **供應鏈安全** - 更強調第三方元件、開源函式庫和 CI/CD 管道的安全風險
- **自動化威脅** - 關注 AI/ML 驅動的自動化攻擊和防禦策略
- **DevSecOps 整合** - 強調將安全整合到開發和部署流程中
- **實際案例更新** - 更新了 2021-2025 年間的真實攻擊案例

### 2025 版本反映的新趨勢

1. **API 優先架構的普及** - RESTful API、GraphQL 成為主要攻擊面
2. **雲端原生應用的安全挑戰** - 容器、微服務、Serverless 架構帶來新的安全考量
3. **供應鏈攻擊的加劇** - Log4j、SolarWinds 等事件凸顯供應鏈安全的重要性
4. **自動化攻擊的演進** - AI/ML 技術被用於自動化漏洞發現和攻擊
5. **零信任架構的採用** - 不再信任內部網路，所有存取都需要驗證

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 3. A01:2025 – Broken Access Control（權限控制失效）

### 3.1 漏洞概述

**定義：** 權限控制失效是指應用程式未能正確實施存取控制機制，導致未授權用戶可以存取本應受限的資源或功能。

**嚴重程度：** Critical（嚴重）

**影響範圍：**
- 敏感資料外洩
- 未授權功能存取
- 用戶資料被篡改
- 系統完整性受損

### 3.2 攻擊原理

權限控制失效通常發生在以下情況：

1. **水平權限提升（Horizontal Privilege Escalation）**
   - 用戶 A 可以存取用戶 B 的資料
   - 例如：`/api/user/123` 可以存取其他用戶的資料

2. **垂直權限提升（Vertical Privilege Escalation）**
   - 普通用戶可以執行管理員功能
   - 例如：普通用戶可以刪除其他用戶

3. **直接物件參考（IDOR - Insecure Direct Object Reference）**
   - 透過修改 URL 參數存取未授權資源
   - 例如：`/api/order/1001` 改為 `/api/order/1002`

4. **功能層級存取控制缺失**
   - API 端點缺少權限檢查
   - 前端隱藏功能但後端未驗證

### 3.3 實際案例

**案例 1：電商網站 IDOR 漏洞**

攻擊者發現訂單查詢 API：
```
GET /api/orders/12345
```

透過修改訂單 ID，攻擊者可以查看其他用戶的訂單資訊，包括：
- 收貨地址
- 電話號碼
- 購買記錄

**案例 2：社交媒體平台權限提升**

攻擊者發現刪除貼文功能：
```
DELETE /api/posts/123
```

雖然前端只顯示「刪除我的貼文」，但後端未驗證貼文所有者，導致攻擊者可以刪除任何人的貼文。

### 3.4 防禦最佳實踐

#### 設計階段防禦

1. **最小權限原則（Principle of Least Privilege）**
   - 用戶只獲得完成任務所需的最小權限
   - 定期審查與撤銷不必要的權限

2. **角色基礎存取控制（RBAC）**
   - 定義清晰的角色與權限
   - 實施角色層級的存取控制

#### 開發階段防禦

1. **統一權限檢查中間件**
   - 在 API 層實施統一的權限檢查
   - 避免在每個端點重複實作

2. **資源擁有者驗證**
   - 驗證用戶是否有權存取特定資源
   - 使用資源層級的權限檢查

#### 程式碼範例

**不安全的實作：**

```javascript
// 危險：未驗證用戶是否有權存取此訂單
app.get('/api/orders/:orderId', async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  res.json(order);
});
```

**安全的實作：**

```javascript
// 安全：驗證訂單屬於當前用戶
app.get('/api/orders/:orderId', authenticateUser, async (req, res) => {
  const order = await Order.findOne({
    _id: req.params.orderId,
    userId: req.user.id  // 驗證資源擁有者
  });
  
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }
  
  res.json(order);
});
```

**使用中間件統一檢查：**

```javascript
// 權限檢查中間件
const checkResourceOwnership = (resourceModel, userIdField = 'userId') => {
  return async (req, res, next) => {
    const resource = await resourceModel.findById(req.params.id);
    
    if (!resource) {
      return res.status(404).json({ error: 'Resource not found' });
    }
    
    if (resource[userIdField] !== req.user.id && !req.user.isAdmin) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    req.resource = resource;
    next();
  };
};

// 使用中間件
app.get('/api/orders/:id', 
  authenticateUser, 
  checkResourceOwnership(Order),
  (req, res) => {
    res.json(req.resource);
  }
);
```

#### 部署階段防禦

1. **定期權限審計**
   - 審查用戶權限分配
   - 識別異常存取行為

2. **監控與告警**
   - 監控權限失敗的嘗試
   - 設定異常存取告警

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 4. A02:2025 – Security Misconfiguration（安全設定錯誤）

### 4.1 漏洞概述

**定義：** 安全設定錯誤是指應用程式、框架、伺服器或雲端服務的設定不當，導致安全漏洞。

**嚴重程度：** Medium（中）

**影響範圍：**
- 未授權存取
- 資訊洩露
- 系統被入侵

### 4.2 攻擊原理

常見的安全設定錯誤：

1. **預設帳號與密碼**
   - 使用預設的管理員帳號
   - 使用弱密碼

2. **錯誤訊息洩露**
   - 詳細的錯誤訊息洩露系統資訊
   - Stack trace 暴露程式碼結構

3. **不必要的功能啟用**
   - 啟用除錯模式
   - 啟用不必要的服務

4. **HTTP headers 設定不當**
   - 缺少安全 headers
   - 暴露伺服器資訊

### 4.3 實際案例

**案例 1：預設管理員帳號**

某系統使用預設的管理員帳號 `admin/admin`，攻擊者可以輕易登入系統。

**案例 2：錯誤訊息洩露**

某 API 的錯誤訊息：
```
Error: Database connection failed. MySQL user 'app_user'@'localhost' access denied.
```

洩露了資料庫用戶名稱與主機資訊。

### 4.4 防禦最佳實踐

#### 設計階段防禦

1. **安全配置基準**
   - 定義安全配置標準
   - 建立配置檢查清單

#### 開發階段防禦

1. **移除預設帳號**
   - 更改所有預設帳號與密碼
   - 強制首次登入更改密碼

2. **設定安全 headers**
   - Content-Security-Policy
   - X-Frame-Options
   - X-Content-Type-Options
   - Strict-Transport-Security

#### 程式碼範例

**設定安全 headers：**

```javascript
const helmet = require('helmet');
app.use(helmet());

// 或手動設定
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});
```

**錯誤處理：**

```javascript
// 不安全的錯誤處理
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,  // 洩露詳細錯誤資訊
    stack: err.stack    // 洩露堆疊追蹤
  });
});

// 安全的錯誤處理
app.use((err, req, res, next) => {
  console.error(err);  // 記錄詳細錯誤到日誌
  
  res.status(500).json({
    error: 'An error occurred'  // 通用錯誤訊息
  });
});
```

#### 部署階段防禦

1. **配置審查**
   - 定期審查配置
   - 使用配置掃描工具

2. **自動化配置管理**
   - 使用 Infrastructure as Code
   - 版本控制配置檔案

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 5. A03:2025 – Software Supply Chain Failures（軟體供應鏈失敗）

### 5.1 漏洞概述

**定義：** 軟體供應鏈失敗是指應用程式使用易受攻擊或過時的元件（函式庫、框架、相依套件），或從不安全的來源取得軟體，導致安全漏洞。

**嚴重程度：** High（高）

**影響範圍：**
- 已知漏洞被利用
- 系統被入侵
- 資料外洩
- 供應鏈攻擊

### 5.2 攻擊原理

常見的供應鏈安全問題：

1. **未更新相依套件**
   - 使用舊版本函式庫
   - 未修補已知漏洞

2. **未監控相依套件**
   - 不知道使用的元件版本
   - 不知道是否有漏洞

3. **供應鏈攻擊**
   - 惡意套件被安裝
   - 合法套件被植入後門
   - 開源專案被惡意修改

4. **不安全的來源**
   - 從未驗證的來源下載軟體
   - 使用未簽章的套件

### 5.3 實際案例

**案例 1：Log4j 漏洞（CVE-2021-44228）**

2021 年發現的 Log4j 遠端程式碼執行漏洞影響全球數百萬應用程式，攻擊者可以透過日誌訊息執行任意程式碼。這是一個典型的供應鏈漏洞，影響所有使用 Log4j 的應用程式。

**案例 2：過時的 jQuery 版本**

某網站使用過時的 jQuery 1.7.2（2012 年發布），存在多個已知 XSS 漏洞，攻擊者可以透過這些漏洞進行跨站腳本攻擊。

**案例 3：惡意 npm 套件**

攻擊者發布看似合法的 npm 套件，但實際上包含惡意程式碼，當開發者安裝這些套件時，惡意程式碼會被執行。

### 5.4 防禦最佳實踐

#### 開發階段防禦

1. **相依套件管理**
   - 定期更新相依套件
   - 使用最新穩定版本
   - 移除未使用的套件
   - 使用鎖定檔案（如 package-lock.json）

2. **漏洞掃描**
   - 整合漏洞掃描到 CI/CD
   - 自動化掃描與通知
   - 設定嚴重程度閾值

3. **來源驗證**
   - 只從可信來源下載套件
   - 驗證套件簽章
   - 檢查套件完整性

#### 程式碼範例

**使用 npm audit：**

```bash
# 掃描漏洞
npm audit

# 自動修復
npm audit fix

# 強制修復（可能破壞相容性）
npm audit fix --force
```

**使用 Snyk：**

```bash
# 安裝 Snyk
npm install -g snyk

# 掃描專案
snyk test

# 監控專案
snyk monitor
```

**CI/CD 整合：**

```yaml
# GitHub Actions 範例
- name: Run security audit
  run: |
    npm audit --audit-level=high
    snyk test --severity-threshold=high
```

**使用 SBOM（Software Bill of Materials）：**

```bash
# 產生 SBOM
npm list --json > sbom.json

# 使用工具分析 SBOM
cyclonedx-bom -o sbom.xml
```

#### 部署階段防禦

1. **持續監控**
   - 監控相依套件漏洞
   - 設定自動化告警
   - 追蹤 CVE 資料庫

2. **應急計畫**
   - 建立漏洞應急流程
   - 準備快速修復機制
   - 建立回滾流程

3. **供應鏈安全**
   - 審查第三方供應商
   - 實施供應鏈安全標準
   - 使用軟體組成分析（SCA）工具

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 6. A04:2025 – Cryptographic Failures（加密機制失效）

### 6.1 漏洞概述

**定義：** 加密機制失效是指應用程式未能正確保護敏感資料，導致資料在傳輸或儲存過程中被暴露。

**嚴重程度：** High（高）

**影響範圍：**
- 敏感資料外洩（密碼、信用卡號、個人資料）
- 資料完整性受損
- 合規違規（PCI DSS、GDPR）

### 6.2 攻擊原理

加密機制失效的常見原因：

1. **傳輸層未加密**
   - 使用 HTTP 而非 HTTPS
   - 弱加密演算法（如 SSL 2.0、SSL 3.0）

2. **儲存層未加密**
   - 敏感資料以明文儲存
   - 使用弱加密演算法

3. **金鑰管理不當**
   - 金鑰硬編碼在程式碼中
   - 金鑰儲存在不安全的位置
   - 金鑰未定期輪換

4. **加密實作錯誤**
   - 使用已棄用的加密演算法
   - 加密強度不足
   - 初始化向量（IV）重複使用

### 6.3 實際案例

**案例 1：密碼明文儲存**

某網站將用戶密碼以明文儲存在資料庫中，資料庫被入侵後，所有用戶密碼外洩。

**案例 2：HTTP 傳輸敏感資料**

某 API 使用 HTTP 傳輸用戶的信用卡資訊，攻擊者透過中間人攻擊（MITM）截取資料。

**案例 3：弱加密演算法**

某應用程式使用 MD5 雜湊密碼，MD5 已被破解，攻擊者可以快速破解密碼。

### 6.4 防禦最佳實踐

#### 設計階段防禦

1. **資料分類**
   - 識別敏感資料
   - 定義資料保護等級

2. **加密策略**
   - 選擇強加密演算法
   - 定義金鑰管理策略

#### 開發階段防禦

1. **使用 HTTPS**
   - 強制所有連線使用 HTTPS
   - 設定 HSTS（HTTP Strict Transport Security）

2. **密碼雜湊**
   - 使用 bcrypt、Argon2 或 PBKDF2
   - 加入 salt（鹽值）
   - 避免使用 MD5、SHA1

3. **敏感資料加密**
   - 加密儲存的敏感資料
   - 使用 AES-256 等強加密演算法

#### 程式碼範例

**不安全的實作：**

```javascript
// 危險：密碼明文儲存
const user = {
  username: 'john',
  password: 'password123'  // 明文密碼
};
await db.users.insert(user);
```

**安全的實作：**

```javascript
const bcrypt = require('bcrypt');

// 安全：使用 bcrypt 雜湊密碼
// saltRounds (cost factor) 建議值：10-12
// 10 = 快速但較不安全，12 = 較慢但更安全
// 根據硬體效能選擇，一般建議使用 10-11
const saltRounds = 10;
const hashedPassword = await bcrypt.hash(password, saltRounds);

const user = {
  username: 'john',
  password: hashedPassword  // 雜湊後的密碼
};
await db.users.insert(user);

// 驗證密碼
const isValid = await bcrypt.compare(inputPassword, user.password);
```

**敏感資料加密：**

```javascript
const crypto = require('crypto');

// 加密敏感資料
// 注意：key 應該是 32 bytes (256 bits) 的 Buffer
// 實際應用中應使用金鑰管理服務（KMS）而非硬編碼
function encrypt(text, key) {
  // 產生隨機 IV（初始化向量）
  // IV 必須是隨機的，且不需要保密，但每次加密都應該不同
  const iv = crypto.randomBytes(16);
  
  // 使用 AES-256-CBC 加密
  // createCipheriv 是正確的方法（createCipher 已棄用）
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  // 將 IV 與加密資料一起儲存（IV 不需要保密）
  return iv.toString('hex') + ':' + encrypted;
}

// 解密敏感資料
function decrypt(encryptedText, key) {
  const parts = encryptedText.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const encrypted = parts[1];
  
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// 實際使用範例（使用環境變數或 KMS）
// const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex'); // 32 bytes
// const encrypted = encrypt('sensitive data', key);
```

#### 部署階段防禦

1. **強制 HTTPS**
   - 設定 HTTP 自動重導向到 HTTPS
   - 設定 HSTS header

2. **金鑰管理**
   - 使用金鑰管理服務（如 AWS KMS、Azure Key Vault）
   - 定期輪換金鑰
   - 安全儲存金鑰

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 7. A05:2025 – Injection（注入攻擊）

### 7.1 漏洞概述

**定義：** 注入攻擊是指攻擊者將惡意資料注入應用程式，導致應用程式執行非預期的指令或查詢。

**嚴重程度：** Critical（嚴重）

**影響範圍：**
- 資料庫資料外洩
- 系統命令執行
- 應用程式完整性受損

### 7.2 攻擊原理

注入攻擊的常見類型：

1. **SQL Injection（SQL 注入）**
   - 在 SQL 查詢中注入惡意 SQL 程式碼
   - 可能導致資料外洩、資料篡改、資料刪除

2. **NoSQL Injection（NoSQL 注入）**
   - 在 NoSQL 查詢中注入惡意程式碼
   - 影響 MongoDB、CouchDB 等資料庫

3. **Command Injection（命令注入）**
   - 在系統命令中注入惡意指令
   - 可能導致系統被完全控制

4. **LDAP Injection（LDAP 注入）**
   - 在 LDAP 查詢中注入惡意程式碼
   - 影響目錄服務

### 7.3 實際案例

**案例 1：SQL Injection 導致資料外洩**

某登入頁面的 SQL 查詢：
```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password'
```

攻擊者輸入：
```
Username: admin'--
Password: anything
```

實際執行的 SQL：
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'
```

結果：攻擊者成功以管理員身份登入。

**案例 2：SQL Injection 導致資料刪除**

攻擊者輸入：
```
Username: admin'; DROP TABLE users;--
```

可能導致整個用戶表被刪除。

### 7.4 防禦最佳實踐

#### 設計階段防禦

1. **輸入驗證**
   - 定義輸入格式與範圍
   - 實施白名單驗證

2. **輸出編碼**
   - 對輸出進行適當編碼
   - 防止 XSS 攻擊

#### 開發階段防禦

1. **參數化查詢（Prepared Statements）**
   - 使用參數化查詢而非字串拼接
   - 讓資料庫區分資料與指令

2. **輸入驗證與清理**
   - 驗證所有輸入
   - 清理特殊字元

#### 程式碼範例

**不安全的實作：**

```javascript
// 危險：字串拼接 SQL 查詢
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
const result = await db.query(query);
```

**安全的實作：**

```javascript
// 安全：使用參數化查詢
const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
const result = await db.query(query, [username, password]);
```

**使用 ORM：**

```javascript
// 使用 Sequelize ORM（自動防止 SQL Injection）
// ORM 會自動使用參數化查詢，防止 SQL Injection
const user = await User.findOne({
  where: {
    username: username,
    password: password  // 注意：實際應用中應先雜湊密碼再查詢
  }
});

// 更好的做法：先雜湊密碼再查詢
const hashedPassword = await bcrypt.hash(password, 10);
const user = await User.findOne({
  where: {
    username: username,
    password: hashedPassword
  }
});
```

**輸入驗證：**

```javascript
const validator = require('validator');

// 驗證輸入
function validateInput(input) {
  // 移除特殊字元
  const cleaned = validator.escape(input);
  
  // 驗證格式
  if (!validator.isAlphanumeric(cleaned)) {
    throw new Error('Invalid input format');
  }
  
  return cleaned;
}
```

#### 部署階段防禦

1. **Web Application Firewall (WAF)**
   - 部署 WAF 阻擋注入攻擊
   - 設定規則偵測異常請求

2. **最小權限原則**
   - 資料庫用戶使用最小權限
   - 避免使用管理員權限

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 8. A06:2025 – Insecure Design（不安全設計）

### 8.1 漏洞概述

**定義：** 不安全設計是指應用程式在設計階段就存在安全缺陷，這些缺陷無法透過實作或配置來修復。

**嚴重程度：** High（高）

**影響範圍：**
- 架構層級的安全漏洞
- 業務邏輯缺陷
- 系統性安全問題

### 8.2 攻擊原理

不安全設計的常見問題：

1. **缺乏威脅建模**
   - 未識別潛在威脅
   - 未設計防禦機制

2. **業務邏輯缺陷**
   - 流程設計不當
   - 缺乏必要的驗證步驟

3. **預設不安全**
   - 預設配置不安全
   - 缺乏安全預設值

### 8.3 實際案例

**案例 1：密碼重置流程缺陷**

某網站的密碼重置流程：
1. 用戶輸入 email
2. 系統發送重置連結到 email
3. 用戶點擊連結重置密碼

問題：重置連結沒有過期時間，且可以重複使用，攻擊者一旦取得連結即可重置密碼。

**案例 2：支付流程缺陷**

某電商網站的支付流程允許用戶在未完成支付的情況下修改訂單金額，導致價格操縱。

### 8.4 防禦最佳實踐

#### 設計階段防禦

1. **威脅建模**
   - 識別威脅與攻擊向量
   - 設計防禦機制

2. **安全設計原則**
   - 最小權限原則
   - 深度防禦
   - 預設安全

#### 開發階段防禦

1. **業務邏輯驗證**
   - 驗證業務流程
   - 實施必要的檢查

2. **安全預設值**
   - 設定安全的預設配置
   - 避免不安全的預設行為

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 9. A07:2025 – Authentication Failures（身份驗證失敗）

### 9.1 漏洞概述

**定義：** 應用程式的身份識別與驗證機制存在缺陷，導致未授權存取。

**嚴重程度：** High（高）

**影響範圍：**
- 帳號被盜用
- 未授權存取
- 身份冒充

### 9.2 攻擊原理

常見問題：

1. **弱密碼政策**
   - 允許弱密碼
   - 無密碼複雜度要求

2. **密碼重置缺陷**
   - 重置流程不安全
   - 重置連結可預測

3. **會話管理缺陷**
   - 會話 ID 可預測
   - 會話未正確失效

4. **多因素驗證缺失**
   - 僅依賴密碼
   - 無額外驗證機制

### 9.3 實際案例

**案例 1：弱密碼政策**

某網站允許用戶使用 `123456` 作為密碼，攻擊者可以輕易破解帳號。

**案例 2：會話固定攻擊**

某網站的會話 ID 在登入前後不變，攻擊者可以誘導用戶使用預設的會話 ID，然後接管會話。

### 9.4 防禦最佳實踐

#### 設計階段防禦

1. **密碼政策**
   - 定義密碼複雜度要求
   - 實施密碼歷史政策

2. **會話管理策略**
   - 定義會話超時時間
   - 定義會話失效條件

#### 開發階段防禦

1. **強密碼政策**

```javascript
const passwordValidator = require('password-validator');

const schema = new passwordValidator()
  .is().min(8)                    // 最少 8 字元
  .is().max(100)                  // 最多 100 字元
  .has().uppercase()              // 必須有大寫字母
  .has().lowercase()              // 必須有小寫字母
  .has().digits()                 // 必須有數字
  .has().symbols()                // 必須有特殊字元
  .has().not().spaces();          // 不能有空格

function validatePassword(password) {
  return schema.validate(password);
}
```

2. **安全的會話管理**

```javascript
const session = require('express-session');
const crypto = require('crypto');

app.use(session({
  secret: crypto.randomBytes(64).toString('hex'),  // 使用強隨機 secret
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,        // 僅 HTTPS
    httpOnly: true,      // 防止 XSS
    maxAge: 30 * 60 * 1000,  // 30 分鐘
    sameSite: 'strict'  // CSRF 防護
  }
}));

// 登入時重新產生會話 ID（防止會話固定攻擊）
app.post('/login', async (req, res) => {
  try {
    // 驗證用戶憑證
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // 重新產生會話 ID（防止會話固定攻擊）
    // 這確保攻擊者無法預先設定會話 ID
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: 'Login failed' });
      }
      
      // 設定會話資料
      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.loginTime = Date.now();
      
      res.json({ success: true });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});
```

3. **多因素驗證（MFA）**

```javascript
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// 產生 MFA secret
function generateMFASecret(user) {
  const secret = speakeasy.generateSecret({
    name: `Fenryx (${user.email})`
  });
  
  // 儲存 secret
  user.mfaSecret = secret.base32;
  await user.save();
  
  return secret.otpauth_url;
}

// 驗證 MFA token
function verifyMFAToken(user, token) {
  return speakeasy.totp.verify({
    secret: user.mfaSecret,
    encoding: 'base32',
    token: token,
    window: 2  // 允許前後 2 個時間視窗
  });
}
```

#### 部署階段防禦

1. **帳號鎖定機制**
   - 多次失敗登入後鎖定帳號
   - 實施 CAPTCHA

2. **登入監控**
   - 監控異常登入行為
   - 設定告警機制

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 10. A08:2025 – Software or Data Integrity Failures（軟體或資料完整性失敗）

### 10.1 漏洞概述

**定義：** 應用程式未能保護軟體與資料的完整性，導致未授權的修改或破壞。

**嚴重程度：** High（高）

**影響範圍：**
- 軟體被篡改
- 資料被修改
- 供應鏈攻擊

### 10.2 攻擊原理

常見問題：

1. **CI/CD 管道不安全**
   - 未驗證建置來源
   - 未簽署建置產物

2. **相依套件完整性**
   - 未驗證套件完整性
   - 使用未簽署的套件

3. **資料完整性**
   - 未驗證資料完整性
   - 未實施資料簽章

### 10.3 實際案例

**案例 1：供應鏈攻擊**

2020 年 SolarWinds 攻擊事件，攻擊者入侵 CI/CD 管道，在軟體更新中植入後門，影響數千家企業。

**案例 2：npm 惡意套件**

攻擊者發布與合法套件名稱相似的惡意套件，開發者誤安裝後，惡意套件竊取敏感資訊。

### 10.4 防禦最佳實踐

#### 設計階段防禦

1. **供應鏈安全策略**
   - 定義套件來源政策
   - 定義簽章驗證要求

#### 開發階段防禦

1. **套件完整性驗證**

```bash
# 使用 npm 驗證套件完整性
npm ci --audit

# 使用 GPG 驗證套件簽章
gpg --verify package.tar.gz.asc package.tar.gz
```

2. **CI/CD 安全**

```yaml
# GitHub Actions 範例
- name: Verify build integrity
  run: |
    # 驗證建置來源
    # 簽署建置產物
    gpg --sign build.tar.gz
```

#### 部署階段防禦

1. **持續監控**
   - 監控相依套件變更
   - 監控建置流程

2. **應急計畫**
   - 建立供應鏈攻擊應急流程
   - 準備快速修復機制

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 11. A09:2025 – Logging & Alerting Failures（日誌與告警失敗）

### 11.1 漏洞概述

**定義：** 應用程式缺乏適當的安全日誌與監控機制，無法及時偵測與回應安全事件。

**嚴重程度：** Medium（中）

**影響範圍：**
- 無法偵測攻擊
- 無法追蹤安全事件
- 無法進行事件回應

### 11.2 攻擊原理

常見問題：

1. **日誌記錄不足**
   - 未記錄安全相關事件
   - 日誌資訊不完整

2. **監控缺失**
   - 無即時監控機制
   - 無異常偵測

3. **日誌管理不當**
   - 日誌未集中管理
   - 日誌未加密儲存

### 11.3 實際案例

**案例 1：未偵測的資料外洩**

某網站被攻擊者入侵並竊取資料，但由於缺乏日誌記錄，直到 6 個月後才發現。

**案例 2：無法追蹤攻擊來源**

某 API 遭受暴力破解攻擊，但由於未記錄 IP 位址，無法追蹤攻擊來源。

### 11.4 防禦最佳實踐

#### 設計階段防禦

1. **日誌策略**
   - 定義需要記錄的事件
   - 定義日誌保留政策

2. **監控策略**
   - 定義監控指標
   - 定義告警規則

#### 開發階段防禦

1. **安全日誌記錄**

```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'security.log' })
  ]
});

// 記錄登入嘗試
function logLoginAttempt(req, success) {
  logger.info({
    event: 'login_attempt',
    ip: req.ip,
    userAgent: req.get('user-agent'),
    success: success,
    timestamp: new Date().toISOString()
  });
}

// 記錄權限失敗
function logAccessDenied(req, resource) {
  logger.warn({
    event: 'access_denied',
    ip: req.ip,
    userId: req.user?.id,
    resource: resource,
    timestamp: new Date().toISOString()
  });
}

// 記錄敏感操作
function logSensitiveOperation(req, operation) {
  logger.info({
    event: 'sensitive_operation',
    userId: req.user.id,
    operation: operation,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });
}
```

2. **異常監控**

```javascript
// 監控異常登入
function monitorLoginAttempts() {
  const recentAttempts = getRecentLoginAttempts(5 * 60 * 1000); // 5 分鐘內
  
  const failedAttempts = recentAttempts.filter(a => !a.success);
  
  if (failedAttempts.length > 5) {
    // 發送告警
    sendAlert({
      type: 'brute_force_attempt',
      ip: failedAttempts[0].ip,
      count: failedAttempts.length
    });
  }
}
```

#### 部署階段防禦

1. **集中日誌管理**
   - 使用 ELK Stack、Splunk 等工具
   - 集中管理與分析日誌

2. **即時監控**
   - 設定即時告警
   - 自動化回應機制

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 12. A10:2025 – Mishandling of Exceptional Conditions（異常條件處理不當）

### 12.1 漏洞概述

**定義：** 異常條件處理不當是指應用程式未能正確處理異常情況（如錯誤、邊界條件、資源耗盡等），導致安全漏洞或系統不穩定。

**嚴重程度：** Medium（中）

**影響範圍：**
- 系統崩潰或拒絕服務
- 資訊洩露
- 未預期的行為
- 安全控制繞過

### 12.2 攻擊原理

異常條件處理不當的常見問題：

1. **錯誤訊息洩露**
   - 詳細的錯誤訊息洩露系統資訊
   - Stack trace 暴露程式碼結構
   - 錯誤訊息包含敏感資料

2. **資源耗盡**
   - 未限制資源使用
   - 無限迴圈或遞迴
   - 記憶體洩漏

3. **邊界條件處理不當**
   - 未處理空值或 null
   - 未處理極大或極小值
   - 未處理特殊字元

4. **異常處理邏輯缺陷**
   - 異常被忽略
   - 異常處理不完整
   - 異常處理後狀態不一致

### 12.3 實際案例

**案例 1：錯誤訊息洩露敏感資訊**

某 API 在發生錯誤時返回詳細的錯誤訊息：
```json
{
  "error": "Database connection failed",
  "details": "MySQL user 'admin'@'localhost' access denied for database 'production_db'",
  "stack": "at Database.connect (/app/db.js:45:12)..."
}
```

攻擊者可以從錯誤訊息中獲取資料庫結構和使用者資訊。

**案例 2：資源耗盡導致拒絕服務**

某 API 端點處理大量資料時未限制處理時間：
```javascript
app.post('/api/process', async (req, res) => {
  const data = req.body.data;  // 可能包含數百萬筆資料
  const result = await processAllData(data);  // 未限制處理時間
  res.json(result);
});
```

攻擊者發送大量資料導致伺服器資源耗盡。

**案例 3：空指標異常導致系統崩潰**

某應用程式未檢查空值：
```javascript
const user = await User.findById(userId);
const email = user.email;  // 如果 user 為 null，會拋出異常
```

當 userId 不存在時，應用程式會崩潰。

### 12.4 防禦最佳實踐

#### 設計階段防禦

1. **錯誤處理策略**
   - 定義錯誤處理標準
   - 分類錯誤類型
   - 定義錯誤回應格式

2. **資源管理策略**
   - 定義資源限制
   - 實施超時機制
   - 實施速率限制

#### 開發階段防禦

1. **適當的錯誤處理**

```javascript
// 不安全的錯誤處理
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,  // 洩露詳細錯誤資訊
    stack: err.stack    // 洩露堆疊追蹤
  });
});

// 安全的錯誤處理
app.use((err, req, res, next) => {
  // 記錄詳細錯誤到日誌（僅伺服器端）
  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });
  
  // 根據錯誤類型返回適當的錯誤訊息
  if (err instanceof ValidationError) {
    return res.status(400).json({
      error: 'Invalid input',
      details: err.details  // 僅包含驗證錯誤，不包含系統資訊
    });
  }
  
  if (err instanceof AuthenticationError) {
    return res.status(401).json({
      error: 'Authentication failed'
    });
  }
  
  // 通用錯誤訊息（不洩露系統資訊）
  res.status(500).json({
    error: 'An error occurred',
    requestId: req.id  // 提供請求 ID 以便追蹤
  });
});
```

2. **空值檢查**

```javascript
// 不安全的實作
const user = await User.findById(userId);
const email = user.email;

// 安全的實作
const user = await User.findById(userId);
if (!user) {
  return res.status(404).json({ error: 'User not found' });
}
const email = user.email;
```

3. **資源限制**

```javascript
// 實施超時機制
const timeout = require('connect-timeout');

app.use(timeout('30s'));  // 設定 30 秒超時

app.post('/api/process', async (req, res) => {
  // 檢查請求大小
  if (req.body.data && req.body.data.length > 10000) {
    return res.status(413).json({ error: 'Payload too large' });
  }
  
  // 實施處理時間限制
  const startTime = Date.now();
  const maxProcessingTime = 10000;  // 10 秒
  
  try {
    const result = await processDataWithTimeout(
      req.body.data,
      maxProcessingTime
    );
    res.json(result);
  } catch (err) {
    if (err.name === 'TimeoutError') {
      return res.status(408).json({ error: 'Request timeout' });
    }
    throw err;
  }
});
```

4. **輸入驗證與清理**

```javascript
function validateInput(input) {
  // 檢查空值
  if (input === null || input === undefined) {
    throw new ValidationError('Input cannot be null');
  }
  
  // 檢查類型
  if (typeof input !== 'string') {
    throw new ValidationError('Input must be a string');
  }
  
  // 檢查長度
  if (input.length > 1000) {
    throw new ValidationError('Input too long');
  }
  
  // 清理輸入
  return input.trim();
}
```

#### 部署階段防禦

1. **監控與告警**
   - 監控錯誤率
   - 監控資源使用
   - 設定異常告警

2. **日誌管理**
   - 記錄詳細錯誤到日誌
   - 不將敏感資訊記錄到日誌
   - 定期審查日誌

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

<div align="center">

## 防禦策略總覽

**建立持續性的安全防護機制**

</div>

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

### 14.1 安全開發生命週期（SDLC）

將安全整合到軟體開發生命週期的每個階段：

#### 需求階段

- [ ] 識別安全需求
- [ ] 進行威脅建模
- [ ] 定義安全標準

#### 設計階段

- [ ] 設計安全架構
- [ ] 定義安全控制措施
- [ ] 設計安全預設值

#### 開發階段

- [ ] 實施安全編碼實踐
- [ ] 進行程式碼審查

#### 部署階段

- [ ] 安全配置檢查
- [ ] 安全監控設定
- [ ] 應急計畫準備

### 14.2 DevSecOps 實踐

將安全整合到 DevOps 流程：

1. **CI/CD 中的安全整合**
   - 自動化合規檢查
   - 程式碼品質檢查

2. **基礎設施即程式碼（IaC）安全**
   - 安全配置模板
   - 自動化安全檢查

3. **持續監控**
   - 即時安全監控
   - 自動化告警
   - 自動化回應

### 14.3 安全框架與標準

#### OWASP ASVS（Application Security Verification Standard）

OWASP ASVS 提供了應用程式安全驗證標準，包含三個等級：

- **Level 1：** 基本安全要求
- **Level 2：** 標準安全要求
- **Level 3：** 進階安全要求

#### NIST Cybersecurity Framework

NIST 網路安全框架提供五個核心功能：

1. **識別（Identify）**
2. **保護（Protect）**
3. **偵測（Detect）**
4. **回應（Respond）**
5. **復原（Recover）**

### 14.4 持續監控與改善

1. **安全監控機制**
   - 日誌集中管理
   - 即時異常偵測
   - 自動化告警

2. **漏洞管理流程**
   - 漏洞識別
   - 漏洞評估
   - 漏洞修復
   - 漏洞驗證

3. **定期安全評估**
   - 定期安全審計
   - 定期風險評估

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 15. 常見問題（FAQ）

### Q1: OWASP Top 10 2025 與 2021 版本的主要差異是什麼？

**A:** 2025 版本對比 2021 版本有以下重大變化：

- **API 安全** - 更多針對 API 的安全建議
- **雲端安全** - 增加雲端環境的安全考量
- **供應鏈安全** - 強調第三方元件的安全風險
- **自動化威脅** - 關注 AI/ML 驅動的自動化攻擊

最終版本可能會調整編號與內容，建議持續關注 OWASP 官方更新。

### Q2: 如何優先處理發現的漏洞？

**A:** 建議按照以下優先順序：

1. **Critical（嚴重）** - 立即修復（24-48 小時內）
   - 可導致資料外洩或系統被完全控制
   - 例如：SQL Injection、權限控制失效

2. **High（高）** - 1 週內修復
   - 可導致敏感資料外洩或未授權存取
   - 例如：加密機制失效、身份驗證失敗

3. **Medium（中）** - 1 個月內修復
   - 可能導致資訊洩露或功能被濫用
   - 例如：安全設定錯誤、日誌監控失敗

4. **Low（低）** - 下次版本更新時修復
   - 影響較小或需要特定條件
   - 例如：資訊洩露風險較低的問題

### Q5: 小型團隊如何實施 Top 10 防禦？

**A:** 小型團隊可以採用以下策略：

1. **優先處理高風險項目**
   - 專注於 Critical 和 High 風險項目
   - 使用現成的安全框架與工具

2. **自動化安全檢查**
   - 整合安全掃描到 CI/CD
   - 使用免費工具（如 OWASP ZAP、Snyk）

3. **尋求專業協助**
   - 定期進行專業安全評估
   - 尋求安全顧問協助

4. **持續學習**
   - 團隊安全培訓
   - 關注安全最佳實踐

### Q3: 如何將 Top 10 防禦整合到開發流程？

**A:** 建議：

1. **開發階段**
   - 實施安全編碼實踐
   - 進行程式碼審查
   - 使用安全框架與函式庫

2. **部署階段**
   - 安全配置檢查
   - 安全監控設定

3. **運維階段**
   - 持續監控
   - 定期安全評估

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

## 16. 總結

### 重點回顧

OWASP Top 10 2025 反映了當前 Web 應用程式安全的主要威脅。作為開發者或資安人員，了解這些漏洞的原理與防禦方法是保護應用程式安全的第一步。

**關鍵要點：**

1. **權限控制失效（A01）** - 是最常見的漏洞類型，需要實施統一的權限檢查機制
2. **安全設定錯誤（A02）** - 提升到第二位，反映配置安全的重要性
3. **軟體供應鏈失敗（A03）** - 新增項目，強調 Log4j 等供應鏈攻擊的威脅
4. **加密機制失效（A04）** - 敏感資料必須加密傳輸與儲存
5. **注入攻擊（A05）** - 仍然是最危險的漏洞之一，必須使用參數化查詢
6. **不安全設計（A06）** - 安全應該從設計階段開始，而非事後補救
7. **身份驗證失敗（A07）** - 需要實施強身份驗證和多因素驗證
8. **軟體或資料完整性失敗（A08）** - 需要驗證軟體來源和資料完整性
9. **日誌與告警失敗（A09）** - 需要實施適當的日誌記錄和監控機制
10. **異常條件處理不當（A10）** - 新增項目，關注錯誤處理和資源管理

### 關鍵學習

1. **安全應該從設計開始**
   - 威脅建模與安全架構設計
   - 安全預設值與最佳實踐

2. **持續監控與改善**
   - 建立安全監控機制
   - 定期安全評估與改善

4. **團隊培訓的重要性**
   - 安全意識培訓
   - 安全編碼實踐培訓

### 下一步行動

**對開發者的建議：**
- 學習安全編碼實踐
- 使用安全框架與函式庫
- 進行程式碼安全審查

**對資安團隊的建議：**
- 建立安全流程
- 整合安全檢查到 CI/CD
- 定期進行安全評估

**對技術決策者的建議：**
- 建立安全開發文化
- 投資安全工具與培訓
- 尋求專業安全協助

### 持續學習資源

- **OWASP 官方資源**
  - OWASP Top 10 2025: https://owasp.org/Top10/2025/
  - OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
  - OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/

- **相關文章**
  - Fenryx 技術部落格
  - 業界專家文章

- **工具與資源**
  - Burp Suite: https://portswigger.net/burp
  - OWASP ZAP: https://www.zaproxy.org/
  - Snyk: https://snyk.io/

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

<div align="center">

## 行動呼籲

### 需要專業的 OWASP Top 10 防禦協助？

</div>

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

### 為什麼選擇 Fenryx？

Fenryx 銳狼科技專注於**以攻擊者視角打造強韌系統**。我們提供：

#### 專業安全服務

- **滲透測試與攻擊工程** - 模擬真實攻擊，找出系統弱點
- **軟體與系統開發** - 從設計階段就融入安全考量
- **系統強化（Hardening）** - 提升系統防禦能力
- **架構與技術顧問** - 建立安全開發流程

#### OWASP Top 10 防禦專案

我們可以協助您：

- **全面安全評估** - 針對 OWASP Top 10 2025 進行完整檢測
- **漏洞修復建議** - 提供具體、可執行的修復方案
- **安全架構設計** - 從設計階段避免安全漏洞
- **團隊培訓** - 提升開發團隊的安全意識與技能
- **持續監控** - 建立自動化安全檢查機制

#### 服務優勢

- **攻擊者視角** - 我們以攻擊者的思維檢視系統，找出真正會被利用的弱點
- **實務導向** - 所有建議都基於真實攻擊案例，確保實用性
- **快速交付** - 敏捷流程，快速識別與修復問題
- **技術透明** - 清楚說明發現的問題與修復方法，讓團隊真正理解

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

### 聯繫我們

<div align="center">

**準備開始強化您的應用程式安全？**

[![Website](https://img.shields.io/badge/官網-fenryx.tech-D72638?style=for-the-badge)](https://fenryx.tech)
[![Email](https://img.shields.io/badge/Email-contact@fenryx.tech-D72638?style=for-the-badge)](mailto:contact@fenryx.tech)
[![Contact Form](https://img.shields.io/badge/聯絡表單-填寫需求-D72638?style=for-the-badge)](https://fenryx.tech/contact)

</div>

<hr style="border: none; border-top: 2px solid #D72638; margin: 2em 0;">

<div align="center">

<img src="https://raw.githubusercontent.com/fenryx-tech/.github/main/profile/assets/logo/logotype.png" alt="Fenryx Logotype" width="500">

**Fenryx 銳狼科技**  
*Engineering Resilience Through Offensive Thinking*  
*以攻擊視角打造強韌系統*

---

*最後更新：2025-11-26*

[![GitHub](https://img.shields.io/badge/GitHub-關注我們-121212?style=flat-square&logo=github)](https://github.com/fenryx)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-追蹤我們-121212?style=flat-square&logo=linkedin)](https://www.linkedin.com/company/fenryx-tech)

</div>