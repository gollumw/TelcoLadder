"""報告的 golden 測試 —— 守的是「重構沒有改變輸出」。

既有的兩條「相同」測試都守不住這件事，這是本檔存在的唯一理由：

- `test_report_is_byte_identical_across_runs` 比的是**同一份程式碼跑兩次**。
  它抓得到「輸出裡混進了時間戳」，抓不到「重構改變了版面」。
- `test_web_output_is_identical_to_the_html_export` 比的是**兩個即時表面**。
  兩邊一起改就一起變，它照樣全綠。

也就是說：在本檔之前，把 `ROW_H` 從 48 改成 60、或把箭頭改成 `<marker>`，
**整批測試都會通過**。而 `render_html.py` 的 SVG 是手工排版的，
那正是最需要被釘住的東西。

**刻意不經 tshark。** flow 是手寫的，所以在 CI 的三個 tshark 版本
（Ubuntu 4.2 / macOS 4.4 / Windows choco）上輸出都一樣。拿真實擷取檔當 golden
會讓 dissector 的版本差異變成 golden 的雜訊，那條路走不通。

**刻意不呼叫 `annotate()`。** cause 說明文字直接寫死在 `detail` 裡，
所以本檔釘的是**渲染器**，不是 cause 查表。改 `data/causes/*.yaml`
不該讓這個 golden 變紅 —— 那是另一件事，有 `test_causes.py` 管。

要更新 golden（**只在你真的想改變輸出時**）：

    .venv/bin/python -m tests.test_report_golden

然後把 diff 看過一遍再 commit。diff 應該只包含你打算做的改動。
"""

from __future__ import annotations

from pathlib import Path

from telcoshark.model import CauseRef, Endpoint, Flow, IdKind, Message
from telcoshark.pipeline import AutoDecode
from telcoshark.render_html import render_report

GOLDEN = Path(__file__).parent / "golden" / "report-synthetic.html"

#: 每個角色群都要出現，因為泳道底色、圖示與協定配色都是按群分的。
#: 少一個群，那個群的 CSS 與圖示就沒有任何測試看著。
UE = Endpoint("10.45.0.2", role="UE")            # 群 ue
GNB = Endpoint("172.22.0.23", port=35786, role="gNB")   # 群 ran
AMF = Endpoint("172.22.0.10", port=38412, role="AMF")   # 群 core
SMF = Endpoint("172.22.0.11", port=8805, role="SMF")    # 群 data
UNKNOWN = Endpoint("192.0.2.77", port=443)              # 群 other（推不出角色，顯示 IP）


def build_flows() -> list[Flow]:
    """涵蓋渲染器每一條分支的合成流程。

    每一則訊息都是為了觸發某個特定分支而存在的，見各自的註解。
    新增渲染分支時請一併在這裡加一則 —— 否則那條分支沒有 golden 保護。
    """
    rich = Flow(
        identity_keys=frozenset({(IdKind.SUPI, "001010000000001")}),
        messages=[
            # 載體＋載荷堆在同一列 → `<tspan class="proto">` 那條分支。
            Message(frame=7, ts=0.0, protocol="ngap", src=UE, dst=GNB,
                    label="InitialUEMessage ▸ Registration request",
                    detail={"protocols": "ngap,nas-5gs"}),
            # 3ms → Δ 不該標警示色。
            Message(frame=8, ts=0.003, protocol="ngap", src=GNB, dst=AMF,
                    label="DownlinkNASTransport"),
            # 跨 2.497s → Δ 要拿到 `class="delta slow"`（SLOW_GAP = 1.0）。
            Message(frame=9, ts=2.500, protocol="sbi", src=AMF, dst=SMF,
                    label="POST /nsmf-pdusession/v1/sm-contexts",
                    detail={"service": "nsmf-pdusession"}),
            # src == dst → 自迴圈，走的是矩形迴圈路徑而不是零長度的線。
            Message(frame=10, ts=2.501, protocol="sbi", src=AMF, dst=AMF,
                    label="internal retry"),
            # 純中文長標籤 → 逼 `_text_width` 的 CJK 分支與 LANE_MAX 夾擠。
            Message(frame=11, ts=2.502, protocol="ngap", src=SMF, dst=UNKNOWN,
                    label="這是一個刻意很長的中文標籤，用來逼出全形字寬度計算與泳道寬度上限"),
            # 失敗＋cause_note → 列高多 CAUSE_ROW_EXTRA，並產出下面的 cause 卡片。
            Message(frame=12, ts=2.503, protocol="nas-5gs", src=AMF, dst=UE,
                    label="Registration reject", is_failure=True,
                    cause=CauseRef("nas_5gmm", 111),
                    detail={
                        "protocols": "ngap,nas-5gs",
                        "cause_note": "5GMM cause #111 —— 合成測試用文字，非查表結果",
                        "cause_plain": "這行是 cause_plain 的位置，用來釘住純文字段落的渲染。",
                        "cause_common": "第一個常見原因\n第二個常見原因",
                    }),
        ],
    )
    # 沒有身分別名 → `describe_identity()` 回「未識別的流程」那條分支。
    # 也沒有失敗 → 配上報告層級的 ciphered，走「未見失敗」徽章。
    quiet = Flow(messages=[
        Message(frame=1, ts=0.0, protocol="ngap", src=GNB, dst=AMF, label="NGSetupRequest"),
        Message(frame=2, ts=0.001, protocol="ngap", src=AMF, dst=GNB, label="NGSetupResponse"),
    ])
    # 截斷要有自己的流程。放在 `rich` 上會把那則失敗訊息砍掉 ——
    # 於是 cause 卡片消失，而 golden 看起來仍然「有內容」。
    # （這個 bug 是 test_golden_actually_exercises_every_branch 抓出來的。）
    noisy = Flow(
        identity_keys=frozenset({(IdKind.AMF_UE_NGAP_ID, "172.22.0.10|172.22.0.23/4")}),
        messages=[
            Message(frame=20 + i, ts=0.01 * i, protocol="ngap", src=GNB, dst=AMF,
                    label=f"UplinkNASTransport #{i}")
            for i in range(8)
        ],
    )
    return [rich, quiet, noisy]


def render_golden() -> str:
    """golden 的唯一產生點。測試與更新腳本共用，不可能分岔。

    `max_messages=6`：`rich`（6 則）完整顯示，`noisy`（8 則）被截斷。
    刻意不讓截斷落在 `rich` 上 —— 砍掉那則失敗訊息會連 cause 卡片一起沒了。
    `ciphered=2` → 觸發加密警告，並讓無失敗的流程拿到「未見失敗」而非「正常」。
    （「正常」徽章由 `test_render_html.py` 的 clean-capture 那條守。）
    """
    return render_report(
        build_flows(),
        source_name="synthetic-golden.pcap",
        ciphered=2,
        # 這份圖是「調整過解碼方式」才有的，報告必須自己講出來 ——
        # 只在 CLI 印、報告裡不印，就是把靜默調整換個介面重演。
        # `AutoDecode` 是純資料類別，建構它不需要 tshark，所以本檔
        # 「刻意不經 tshark」的前提仍然成立。
        auto_decode=AutoDecode(
            relaxed_seq=True,
            synthetic_directions=2,
            decode_as=("tcp.port==7070,http2",),
            messages_before=211,
            messages_after=380,
        ),
        max_messages=6,
    )


def test_report_matches_golden() -> None:
    """報告輸出必須逐位元組等於 committed 的 golden。

    這條紅了代表你改變了報告的輸出。那可能完全正確 —— 但必須是**刻意**的：
    看過 diff、確認每一處都是你要的，再用本檔 docstring 裡那行指令更新。
    """
    assert GOLDEN.exists(), (
        f"找不到 golden：{GOLDEN}\n"
        "第一次建立請跑：.venv/bin/python -m tests.test_report_golden"
    )
    assert render_golden() == GOLDEN.read_text(encoding="utf-8"), (
        "報告輸出與 golden 不同。若這是刻意的改動，看過 diff 之後跑：\n"
        "    .venv/bin/python -m tests.test_report_golden"
    )


def test_golden_actually_exercises_every_branch() -> None:
    """golden 若沒真的踩到那些分支，它就只是在守一份空白。

    這條擋的是「有人把合成資料簡化掉，golden 還在但已經沒有保護力」。
    """
    html = render_golden()
    # 樣式表內嵌在同一份文件裡，而它含 `.cause-ref`、`.delta.slow` 這類選擇器。
    # 不先剝掉 `<style>`，這些斷言會比對到 CSS 而不是內容 —— 假通過。
    # （寫這條測試時第一版就是這樣自己騙過自己的。）
    head, _, rest = html.partition("<style>")
    _, _, body = rest.partition("</style>")
    html = head + body
    for needle, why in [
        ('class="delta slow"', "慢間隔警示"),
        ("NGAP,NAS-5GS", "wire 視圖的協定堆疊標籤"),
        ('badge fail', "失敗徽章"),
        ('badge unknown', "未見失敗徽章（加密時不得標正常）"),
        ("已截斷", "截斷公告"),
        ("--max-messages", "截斷公告要指名旗標"),
        ("已加密", "加密警告"),
        ("解碼方式經過自動調整", "自動調整公告"),
        ("--no-auto-decode", "自動調整公告要講怎麼關掉"),
        ("cause-ref", "cause 卡片"),
        ("第二個常見原因", "cause_common 多行"),
        ("未識別的流程", "無身分流程"),
        ('class="lane-box ue"', "泳道群 ue"),
        ('class="lane-box ran"', "泳道群 ran"),
        ('class="lane-box core"', "泳道群 core"),
        ('class="lane-box data"', "泳道群 data"),
        ('class="lane-box other"', "泳道群 other"),
    ]:
        assert needle in html, f"golden 沒有涵蓋：{why}（找不到 {needle!r}）"


if __name__ == "__main__":  # pragma: no cover - 更新 golden 用
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN.write_text(render_golden(), encoding="utf-8")
    print(f"已寫入 {GOLDEN}（{len(render_golden())} 字元）")
