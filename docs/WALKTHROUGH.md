# TelcoLadder 語意色調校與視覺系統完成報告

## 1. 語意色調校：Lightness 嚴格拉齊（L = 0.720–0.721）

依據回饋，我們放棄物理上無法在 sRGB 取得一致的「等 Chroma」限制，改採**「Lightness 嚴格拉齊至 0.72、Chroma 各自取各色相在 sRGB 色域上限的 ~88%」**。

### 1.1 最終色碼與實測反算值（OKLCH 反算）

> 計算基準：標準 OKLab/OKLCH 轉換式（Björn Ottosson, 2020），畫布底色 Canvas: `#090d16`（反算 OKLCH: `0.160 / 0.0203 / 265.6°`）。

| 語意角色 | 最終色碼 (sRGB) | 反算 Lightness (L) | 反算 Chroma (C) | 反算 Hue (H) | 對比度 (對 Canvas `#090d16`) | WCAG 評級 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Fail** (玫瑰紅) | `#f67a73` | **0.721** | 0.1534 | 24.9° | **7.36:1** | AAA (7:1) ✓ |
| **Warn** (琥珀金) | `#d59733` | **0.720** | 0.1336 | 74.9° | **7.68:1** | AAA (7:1) ✓ |
| **OK** (翡翠綠) | `#3ac178` | **0.721** | 0.1571 | 155.0° | **8.40:1** | AAA (7:1) ✓ |
| **Accent** (訊號青) | `#39b6d0` | **0.720** | 0.1120 | 214.8° | **8.12:1** | AAA (7:1) ✓ |

- **Lightness 最大跨度**：
  $$\Delta L = L_{\max} - L_{\min} = 0.721 - 0.720 = \mathbf{0.001}$$
  （遠在要求之 $\pm 0.02$ 內，四色在感知與灰階下視覺份量完全一致）。
- **對比度餘裕**：全部大幅超越 WCAG AA（4.5:1）與 AAA（7.0:1）標準。

---

## 2. 測試與不變量守護

1. **前端編譯**：
   - `npm run build`：0 警告，產出 `telcoladder/static/app.{js,css}`。
2. **測試套件**：
   - `pytest`：**514 passed in 136s**（包含後端解碼樹 PDML `show` 屬性新增的 2 項測試與全部 19 項資產不變量測試）。
3. **PORTED.json 釘住**：
   - `SessionAnalysisView.tsx`（`c1ac3dbc0e37f1d2a280f4d2a7fd3bf1592afff8abcad3065d095352e1f68410`）與所有分岔檔案雜湊精確記錄。

---

## 3. 截圖產物清單

所有截圖已同步輸出至 `docs/images/` 與 Artifact 目錄：

![08 - Grayscale Failure View (ki-mismatch)](images/08_grayscale_ki_mismatch.png)

![07 - Grayscale Preview (5gc-e2e)](images/07_grayscale_preview.png)

![06 - 600px Responsive View](images/06_responsive_600px.png)

![03 - 5gc-e2e Call Flow Ladder](images/03_5gc_e2e_call_flow.png)

![04 - ki-mismatch Failure Color](images/04_ki_mismatch_failure.png)

![01 - Home Page Dark Dropzone](images/01_home_page.png)

![02 - 5gc-e2e Data Mining & Drawer](images/02_5gc_e2e_data_mining.png)

![05 - unknown-dnn Warning Banner](images/05_unknown_dnn_banner.png)

README 預覽圖 [`docs/images/browser.png`](images/browser.png) 已更新為最新渲染結果。
