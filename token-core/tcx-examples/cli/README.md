# Token Core CLI Demo

同時提供 **CLI**（命令列）與 **CLI UI Tools**（React + Vite）的 EVM 交易理解 Demo。
目標是讓不熟悉區塊鏈的使用者，也能看懂一筆交易在做什麼、有哪些風險、模擬結果如何，以及是否要送上鏈。

## 目錄

1. [一、專案簡介與功能概覽](#一專案簡介與功能概覽)
2. [二、前置環境](#二前置環境)
3. [三、快速開始與環境設定](#三快速開始與環境設定)
4. [四、CLI 使用說明](#四cli-使用說明)
5. [五、CLI UI Tools 使用說明](#五cli-ui-tools-使用說明)
6. [六、其他、總結與參考](#六其他總結與參考)

## 一、專案簡介與功能概覽

### 兩條操作路徑

| 路徑             | 適合情境                                        |
| ---------------- | ----------------------------------------------- |
| **CLI**          | 命令列操作、自動化流程、批次分析、簽名與廣播    |
| **CLI UI Tools** | 互動式 Demo、視覺化解說、交易模板建立與逐步確認 |

### CLI 功能概覽

- **錢包管理**：`wallet create` / `wallet import` / `wallet list`，支援 CLI UI Tools / CLI 共用錢包檔格式
- **交易分析**：`analyze` — 解析 tx request JSON 或 signed raw tx，輸出繁中摘要、policy 檢查與模擬結果
- **簽名與廣播**：`sign` / `broadcast` — 均附 policy 預檢，違規直接中止

### CLI UI Tools 功能概覽

- **建立 Token Core 帳號**：瀏覽器端建立錢包，可下載 CLI UI Tools / CLI 共用錢包檔
- **建立常見交易模板**：ETH 轉帳、ERC-20 transfer / approve、WETH、自訂 calldata
- **Decode 與模擬**：合約驗證、風險提示、繁中 AI 摘要、policy 結果、Tenderly 資產變化
- **送上鏈**：Token Core 路徑 — 簽名後廣播 signed raw tx

## 二、前置環境

| 工具    | 版本要求              | 確認指令        |
| ------- | --------------------- | --------------- |
| Node.js | ≥ 20.19（或 ≥ 22.12） | `node -v`       |
| npm     | ≥ 9                   | `npm -v`        |
| Git     | 任意版本              | `git --version` |

使用 Homebrew 快速安裝（macOS）：

> 注意：本專案使用 Vite 8，Node.js 需符合 `20.19+` 或 `22.12+`。

```bash
# 安裝 Homebrew：https://brew.sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install git mise
brew install --cask visual-studio-code
mise use --global node@24
```

## 三、快速開始與環境設定

### 快速開始

```bash
# 下載專案（指定 demo 分支）
cd ~/Desktop/
git clone --branch demo/token-core-cli https://github.com/consenlabs/token-core-monorepo.git

# 安裝依賴並設定環境變數
cd token-core-monorepo/token-core/tcx-examples/cli/
# 建議開發時使用 npm install；若發生版本不相容或環境報錯，請改用 npm ci 以確保與鎖定檔完全一致
npm install
cp .env.example .env   # 複製範本後填入所需 API Key

# 使用 CLI
npm run cli -- --help

# 啟動 CLI UI Tools（預設 http://localhost:5173）
npm run dev
```

> 修改 `.env` 後需重新執行 `npm run dev`，Vite 的 `import.meta.env` 僅在啟動時讀入。

### 環境變數

所有可用的環境變數均列於 `.env.example`，建議儘量填寫以獲得最完整的功能。

#### Alchemy API Key

取得：[Alchemy Dashboard](https://dashboard.alchemy.com/) → 建立 App → 複製 API Key

```
VITE_ALCHEMY_API_KEY=your_key
```

本專案會自動組出 `eth-sepolia` 與 `base-sepolia` 的 RPC URL。

#### Etherscan API Key

取得：[Etherscan API Dashboard](https://etherscan.io/myapikey) → 建立 Key

```
VITE_ETHERSCAN_API_KEY=your_key
```

Etherscan V2 為多鏈共用 key，Sepolia 與 Base Sepolia 共用同一把即可。

#### Tenderly Node Access Key

取得：[Tenderly Dashboard](https://dashboard.tenderly.co/) → **Node RPCs** → 選擇或建立 Node → **Settings** → 複製 **Access Key**

```
VITE_TENDERLY_NODE_ACCESS_KEY=your_key
```

本專案使用下列 gateway URL（單一 key 覆蓋所有支援鏈）：

- `https://sepolia.gateway.tenderly.co/<NODE_ACCESS_KEY>`
- `https://base-sepolia.gateway.tenderly.co/<NODE_ACCESS_KEY>`

若希望在 CLI / CLI UI Tools 顯示可分享的模擬連結，需額外填入以下三個變數（皆在同一 **Settings** 頁面取得）：

```
VITE_TENDERLY_ACCOUNT_SLUG=your_account_slug
VITE_TENDERLY_PROJECT_SLUG=your_project_slug
VITE_TENDERLY_ACCESS_TOKEN=your_access_token
```

> `Node Access Key` 與 `Access Token` 用途不同，請勿混用。

#### CLI 設定

```
TOKENCORE_CLI_HOME="./.tokencore-cli"   # CLI 錢包目錄，預設 ~/.tokencore-cli
TOKENCORE_CLI_PASSWORD=                 # 非互動式密碼（建議用 shell env 或 CI secret 設定）
```

#### Gemini API Key（AI 摘要）

取得：[Google AI Studio](https://aistudio.google.com/) → 建立新 GCP Project → 建立 API Key

```
VITE_GEMINI_API_KEY=your_key
```

> 每個 GCP Project 有獨立每日配額。遇到 429 時，建立新 Project 取得新 Key 即可重置。

#### Groq API Key（AI 摘要備緩）

取得：[Groq Console](https://console.groq.com/) → **API Keys** → **Create API Key**（免費帳號，不需信用卡）

```
VITE_GROQ_API_KEY=your_key
```

若兩個 AI key 均未設定，本專案仍會顯示本地規則生成的繁體中文摘要。

> `VITE_*` 變數會被打包進瀏覽器 bundle，請只使用 demo / dev key，勿放正式憑證。

## 四、CLI 使用說明

### 錢包管理

建立新錢包（`--password` 省略時以互動方式隱藏輸入；腳本化請使用 `TOKENCORE_CLI_PASSWORD`）：

```bash
npm run cli -- wallet create --name demo-cli --chain eth-sepolia
```

匯入 CLI UI Tools 下載的共用錢包檔：

```bash
npm run cli -- wallet import --chain eth-sepolia --wallet ./demo.wallet.json --name imported-wallet
```

列出所有已管理的錢包：

```bash
npm run cli -- wallet list
```

#### 領取測試 token

**Sepolia ETH**

1. 前往 [Sepolia PoW Faucet](https://sepolia-faucet.pk910.de/)
2. 填入錢包地址 → **Start Mining** → 等待後 **Claim Rewards**

**Sepolia USDC / EURC（ERC-20）**

1. 前往 [Circle Testnet Faucet](https://faucet.circle.com/)
2. 選擇 **USDC** 或 **EURC** → Network 選 **Ethereum Sepolia** → 填入地址 → **Send**

### 分析、簽名與廣播

分析 tx request JSON 或 signed raw tx：

```bash
npm run cli -- analyze --chain eth-sepolia \
  --input '{"chainId":11155111,"account":"0x...","to":"0x...","data":"0x...","value":"0"}' \
  --policy ./src/policies/default-risk-policy.json
```

簽名（`--password` 選填；`--policy` 必填）：

```bash
npm run cli -- sign --chain eth-sepolia \
  --input '{"chainId":11155111,"account":"0x...","to":"0x...","data":"0x...","value":"0"}' \
  --wallet <wallet-name|path> \
  --policy ./src/policies/default-risk-policy.json
```

廣播已簽名 raw tx：

```bash
npm run cli -- broadcast --chain eth-sepolia --input '0x02f8...' \
  --policy ./src/policies/default-risk-policy.json
```

若 `--input` 為未簽名 tx request JSON，`broadcast` 會先簽名再廣播（需同時提供 `--wallet`）。

測試網出塊較慢時，可加 `--wait-timeout 300000`（預設 180000 ms，即 3 分鐘）。

### Policy

`src/policies/` 目錄內建多份範例 policy，CLI UI Tools 與 CLI 均可使用。
可直接複製後自訂，透過 `--policy <path>` 或 `--policy '<inline-json>'` 指定。

### CLI UI Tools / CLI 錢包檔互通

CLI UI Tools 的「下載共用錢包檔」與 CLI 的 `wallet import` 使用同一種格式，可直接互通：

```bash
npm run cli -- wallet import --chain eth-sepolia --wallet ./demo.wallet.json --name imported-wallet
```

## 五、CLI UI Tools 使用說明

CLI UI Tools 提供五個互動區塊，從設定 policy 到送上鏈，逐步引導完整交易流程。

| 區塊                  | 功能                                                 |
| --------------------- | ---------------------------------------------------- |
| 區塊 1：Policy 規則   | 載入或貼上 Policy JSON，設定允許條件                 |
| 區塊 2：建立帳號      | Token Core 錢包建立、匯入與瀏覽器端暫存              |
| 區塊 3：建立交易模板  | ETH、ERC-20、WETH、自訂 calldata                     |
| 區塊 4：Decode 與模擬 | 合約驗證、風險摘要、policy 結果、Tenderly 模擬       |
| 區塊 5：送上鏈        | Token Core 簽名後廣播，顯示 receipt 與 explorer 連結 |

CLI UI Tools 與 CLI 共用核心 decode、模擬與 policy 邏輯；CLI UI Tools 下載的錢包檔可直接交給 CLI 使用。

## 六、其他、總結與參考

### 無 API Key 時的 Fallback 行為

| 缺少的 Key    | 退化行為                                                  |
| ------------- | --------------------------------------------------------- |
| Etherscan     | 退回 Sourcify 與內建 ABI / selector 規則                  |
| Tenderly      | 退回一般 RPC 模擬、gas estimation 與規則型 token 變化推估 |
| Gemini + Groq | 只顯示本地規則生成的繁體中文摘要（永遠可用）              |

### 安全說明

- CLI UI Tools 的 `keystore`、助記詞與密碼均在瀏覽器端操作，僅適合 demo / 測試網，不建議承載正式資產
- CLI 請勿將密碼寫進 shell history；建議使用互動式隱藏輸入，或在受控環境下使用 `TOKENCORE_CLI_PASSWORD`
- 遇到合約未驗證、selector 無法辨識、模擬失敗或 policy 違規時，應視為高風險訊號，送出前務必再次確認

### 驗證指令

```bash
npm run verify          # 完整驗證（lint + typecheck + 所有測試 + build）
npm run test:unit       # 單元測試
npm run test:cli        # CLI 整合測試
npm run test:smoke:chains  # Sepolia / Base Sepolia 雙鏈相容性回歸
npm run test:ui         # UI 元件測試
npm run audit:high      # npm 供應鏈安全掃描（high severity gate）
```

### 主要技術參考

- [Viem](https://viem.sh)
- [Token Core WASM (`@consenlabs/tcx-wasm`)](https://www.npmjs.com/package/@consenlabs/tcx-wasm)
- [Etherscan V2 API](https://docs.etherscan.io/api-reference/endpoint/getsourcecode)
- [Sourcify API](https://docs.sourcify.dev/docs/api/)
- [4byte Directory](https://www.4byte.directory/docs/)
- [Tenderly Simulation](https://docs.tenderly.co/simulations)
- [Gemini API](https://ai.google.dev/gemini-api/docs)
