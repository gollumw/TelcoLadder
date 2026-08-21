"""TelcoLadder —— 電信信令封包轉 Mermaid 時序圖。

Phase 1 涵蓋 5G 核網（NGAP / NAS-5GS / PFCP / HTTP-2 SBI / GTP-U）。
Phase 2 主攻 IMS（SIP / Diameter / GTP）—— 協定以 adapter 形式插拔，
核心資料模型 (`telcoladder.model`) 已預留跨協定的身分關聯欄位。
"""

__version__ = "0.1.0"
