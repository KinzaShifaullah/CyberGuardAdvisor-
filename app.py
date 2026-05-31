# ============================================================
# app.py  –  CyberGuard Advisor  (Final Version)
# Rule-Based Cybersecurity Expert System
# BS-CS Artificial Intelligence Term Project · 2026
# ============================================================
import streamlit as st
import sys, os, base64, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from inference_engine import (
    extract_password_facts, extract_url_facts,
    extract_message_facts, extract_scam_facts,
    extract_hygiene_facts, run_inference, resolve_conflicts,
)
from confidence_engine   import build_score_report
from explanation_engine  import generate_explanation, format_full_report
from recommendation_engine import get_recommendations
from certainty_factor    import build_cf_report
from backward_chaining   import run_backward_chaining
from test_scenarios      import TEST_SCENARIOS
from knowledge_base      import RULES

# ── Page config ─────────────────────────────────────────────
st.set_page_config(
    page_title="CyberGuard Advisor",
    page_icon="assets/hero1.jpeg" if os.path.exists("assets/hero1.jpeg") else "🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

def img_b64(path):
    try:
        with open(path,"rb") as f: return base64.b64encode(f.read()).decode()
    except: return None

import os
HERO_IMG = "/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/2wBDAQMDAwQDBAgEBAgQCwkLEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBD/wAARCADJASsDASIAAhEBAxEB/8QAHgAAAgICAwEBAAAAAAAAAAAABgcFCAMEAAIJAQr/xABZEAABAwMDAQUEBAkFCgoLAQABAgMEAAURBhIhBwgTMUFRFCJhcRWBkaEJIzJCUpKxwdEWM1NiohckQ3KCwsPS0+ElNWNlc4OTo7KzGCY0RFRkdISFpbTw/8QAHAEAAQUBAQEAAAAAAAAAAAAAAwECBAUGAAcI/8QAOBEAAQQBAgMFBgUDBAMAAAAAAQACAxEEEiEFMUETIlFx0QaBkaGxwRQVMmHwByMkQmLh8TNSov/aAAwDAQACEQMRAD8A9I+oGsp+k1W9MGPHcMzvd3epUcbdmMYI/SNBr3WfUDBwq3QFH0S05/r1l693OLb39OpkvBvvTKCcnxx3X8aBI0yO4jLKm3SR65pLXIne64auByza7XjyCmXSf/MrujrVrMoK12u0NgAqKltuJSkDxJJcwAKH0MqeAcDQyD6Um+2Be5Nj6PqZZkLY+lLgxEcKDgqb5WpPyITg0SNutwamudpFp9W/tDyrk4WYV60XJcBwUsTUrOfTAdNTzfVXVy8YttsXnzQ24QfsXXkC2nvk72SSPAYqdtd81BZ0D6MvVwhkeHs8lbfP+SRVl+VvLdQv4KAOJQl5ZrFjpYtetx6maiSgKXb4QJ/5Jf8Ar1s27Xmq7g8G0QICUnz7pf8Ar15f2DrX1dtaAqPr+9jacgPSS6P7eaLo/a+652GMp5OqI0lLYziTCbIPz2gUF2A9vVSmztdyXpy3ep+wF1DG4+iSP311N9ng8NM/qn+NebOlvwjnV6U4tFz0dYrg20cFTRW0T+2juB+EmZjY/lJ0sltjHvKiSwvH1KApn4Z4HJcZVev6enf0TP2H+NfPp6f/AETH2H+NVI0/+EZ6I3fCbjbL9bVH9NgOY/VNMSzdrfoXe0pXH1oiPu8pTK2/3GmmE/8Aqu7TxKef09cf6Fj9U/xr4b9cQM9yx+qr+NAto6vdMr2E/R+urK4VeAMpKM/rYogRerXKTmBcY0kHzYdS4P7JNDMddE/tB4qZ/lBcfJlj9U/xrp/KK5A47mP+qr+NRIubIdS0V+8rgA+dbSsKBKuKTTXRcHA8itz+Uk/w7lj9U/xrh1LPH+BY/VV/Gop6QyjgrSPrromQy4cBY+2u0/suDr6qX/lNcP6Fj9VX8axDVVyIP4iNx/VV/Go1wlKdya6e64keR86UAc6XElSKtX3EHHcRv1Vf61d/5VXRScpbij5oUf8AOqEfRtPuiseV+SsUoa2l1lTDuq9QJGW0W/62l/69L/UXXLV1nui4EeDZnEt+KlMu5+5yiKc8qPBefUvGxJOfTikJPfXLmPyFKKi4snJprmtanx7ndHN47SeuoMYKi2mxLeWralKmHiD9joqMmdqDqZDfaQqyacKAje+fZ3+Pl+OoMeitvOIccRko5HwrUulvMuK62gDK04zTaHNHaBdJlWrtR6turHfN2yxgkkAdy9/ta2z2j9c84tVj+th7/a1XcW2fAusNmIlaWmgd3oTRFp26O3ZySw+yULYVtAPmKaD1KK+JrVYbS/W7Vl63rmw7M2lPgG2XQfvcNTMzqvfmmlmPHtm8A43trIz9S6r7HvTdikIS+6W0unAx5mpKZqNnuSre6getNtA0Wdlj6k9qPtI6Ud36e0tomfHKyB3kCWpQHlnEofsoSg9tLtSOq/v3Q2h2h8LZNz//AFV3uGrrc0drz/efA81HL11byvCYZUB5hNIXbJezRhB7YHXl9I7/AErpEHzxb5af2yDUojtY9bFjKdJ6XV8osgf6egmL1AsyGwhdrTuPidlZ0X+zSveRHLW70phdfVOAHgi17td9YGMb9Iad+P8Aesj/AG1fU9sfqMgAytPaeQfzh7NIz/51CbTludeKw4rj1TwayPsWeQr3m2SrHOabbvFKAOoTH0V2r9W6n1ZZbBJtVjbZudxjQ3C2w8FhLjqUEpy6RnB4yDVo6o9oaxWcdR9MSm2mw6i8wlJ2nzD6DV4afGSRuhProq49r+PMfd0f7I2VbfpDdjy/9nxSl0vC1AXm1NreGePE1arqnamLmq198w253QfxvHhnu/D7KAmbOw06lsRktgcAgeFOTFE2lE2O2PaCsrOPEcVX38INcksdNNMRgAkuXorI9QmO5+8irQSltQlJQ6CrPhgVTf8ACM3NJsmiYTCiA9JmOqB8tqWxn+3RoDUgKZILCrDpdQft4cPmtVELDaAvwoe0k0GLMykOpXklW5PhyaImTg5Br03CFYzPILwHjj9fE5z/ALj9VOW9ptZBUkGii36csl2Z9nuFvacbcBChjH3ihi3E+NGVldKUJz4Uk0bXbuFqLi5c8Lv7byPIlSmnujGgAlSI0B+Nv8S28f35qUl9m3TFzaPs95ltlXgHEpUB9wqXsErATz50dW2UkoHIqnmgaDsFq8TjOYxv/lJ89/qq+Xjsh3JtYftGo4LyhyA60pr6iRmha79COstpz9G2eBPA8BGmpST/ANptq3a5ORwa1lu45zQGYzSph9p82PmQfMeipkzpfqzallu79O73hJyVsxy+B9be4VJM3zUFtwh1672twfmOd6wQfkcVcKC9lYyaM7Qttxru3EJUkjBSQCDTZINA33UzF9qpJjUkY9xr1VHWetvVfT5zaOoF5Z2cgCUoj76LLL2yOvlvaR32rW5Y/RlQ23Mj5kZq3Vw6b9O782Rd9DWGSpXitdva3/rbc/fQFf8Asz9GJ5UprSAhqOfeiynm/wCzuKfuqH2LXmyFbj2hhjFvafkfRI249vvXtpUhu8aUs8/P5Sm3HmF/MbVbfuok0p+EO07ptK7pqfQ98eRJOSGrkhxLYH6KVIB++s2oexF04vMgSYeob/DUnwQp5t1v7CkH76D9W9gWbdYRZ091CjpVghKZcJSEj5lKifuoc2NKGENCJj8b4TJKJHuIcP2P22Tvsv4Tns03Hai7SdQWdSvH2iAFoH+UhR/ZTH0t2x+zTrOWzE0/1dsftEggJZlOKjqJPl+MAH315qak/Bw9fIRcdt8/Tt5wSUiPMLRI/wCtCaQ/VLor1M6ITYDOvrF9Fuz95irRIQ6HNmNxCkE+G4fbUI4z2jvClcwcRxcl2mGQEnpe/wAF+ght9qS0h1paVoWNyVJOQQfMV0W2kc1X7sK63uerugmmzf5BdmJiJ2rPitAJSD9iQPqp9X27QbBAcuNxUUMNDK1AZwKjAdFOsVaidYyBH07LUk8qTtH10kH3BGZU874IGTR1duqWjdZW6Ta9P3ASX0FKlbR4DP8AuoDv8ZblpkpQOdhqHnl+Oxzq3AJpSsPTM5tHYlV71n1t17Y9SP8AskBhVujq3EHxWmmt0v6n2bqRai9EWlqW17r0dRwpJ+VKzqFodOobWXIj22S0MjHn8KCumdo1tbL0zOs1lMV6O7teeJwl1HmCKh+x+azj+NI2Q1K2r3/nNXftc6DAixpYGgA2HUN+lFW8cgIWj3Ujd61rQrGIU9UpoHD35Y+NSdleVcrY3IwkPbfxgHkrzrN3j6cpUkePpVk9hb3T0VFHIHDW3qozUGm275BVGOUODltY/NVS7uGo75Z3BpvUUdLS/BqRg7XR5c+tOKE6Fr2Oj66xal0XbNXW5cCeyCCPxbgHvIV5EVz22E5r6KRzsyIFcMtrJ8zW5EMF7juQ2SPEc1q3fQl30pO9hnoW43n8S9jhafj8a34NsS3CW6oKS8o4QD51DILTupgLSLXdFutshBIkDdW01a2oyd5mIIPgK6s2mS02CprJPPFdn7S9I4AIptodbraZjyVp3MlKgPDCq7pt8xed7CzmopNtusdQ7nvcJ8xW4zJ1CyoJT3p+JrtR6LkSdPYC2eoemFutuJIvELG7j/Doq8tUi6cXK4yNfacZlt7j9Lw+VDkDvk81d2jRckCXmEvurC5TQtbkZClY7/IT/wBXigZufMcTl5tSSPUUzNfsvLRCdZxuR3nBHjnb/ChZtiU4zl1lsg+OcU880EqC7xErCXEe95E1Sv8ACENJdv2jbacYahTXiP8AHcaA/wDAavT7FEccCdqkqzjgcVRDt7y2h1WtFtUriPp9tzk+G990f5oo8A726Y88qVfbBHTHtMdpI8E/vqZjeWajbepIhMpSRwkVIMkoAJNeoY7dMTG/sF888Sfry5X+Lj9VNwVYOAaI7fL27UZ+yhCO+QMpxU5bnicKI5p722FXdpR2TIsk0AABVFTt/wDoi0SbmWVyPZWy53SDgrPgAD5ZJFLm1SiCAPHNGMtJOjSvxVMuVvjY89ipjIUPszVZljS0u6q54Y4TzMY7lYtET9w1XFjiRfrppfSzKgPemye/dHyBKUmtGDKM2eG9PdS2brcVf+6XGGY0eSPHDJ2jn4pKvjUt040/YrmbvqWbaYkmfKvlybMh1sLXsZlOMISCfIBoY+FHl20vY9RQDbbtamH2DyEqQBtPkUkcpI9RVLbz3rWtPYs/t6R++w+9n5oJg6nhonItd2iPWW5q932WXgJdPqy5+S4PgPe+FH9mknjmlRq63zojGotCS7g5dYEaHaHYK5oC5MZ2ZMdYCA74qALYKSr3+fyjTTbZMWWpoDG08fKisldLbX9FW5OM3FIkZyP/AAfujOK/ub48a6PjcnmtGA+do58K3VrCk4xTNJBSufrbS0F5SquJklsHOMYrkk7VGouRKCcipLW6lUTSCM2VILuATnmvOD8JjflTupWlrI0sFMO0KfIz4LceUP2ITV+ZNwwcA15ldte4K1P2ljZ0rKm2GIMLI5/LSlR+9ZoHEG9nBfiQrn2NmOTxYf7Wk/QfdelPZpssrSnQfRKrekJmQbc06pI/wiFjeof2qsVBk27V9iS6pCXWZKClxB5wfMEUo9Asv2bR1ltZh7ERYDLA97nCUBI/ZW7prVK9E6xTbZwULNel4bdP5LEg+R9Ar9tZYP7xIXr5btai0dGE6Ovt1u9tSRCeTlKf0eScffXxURDramlpBCgQRTyu0YTLa+z+m2cfZSjMJaHFJWggg45GKbMXSOt+6KxwaO4K8kmdU6Sm2yYp1pJEV05CwMhPzr5YI7QYLfCilRyQMZp3ptqH0Ft1oLTjlJGQaVNu6h2WR1Fe0Rbum12cdYd7t6V3QSyPiCSMj5VXcL4fHwnJM2OKa67CjcSbNxGtb7I8US6Nive1rQ2ghkjKvTNFr9ifeO5pOanIVocbbTuhNRGwPDcM13lOWi3pJcu7TC/HKnBVxPL2zy5JiQmBmi7UE3piTwpwJQD68VN2+ylCAgqSrB8QaC9eu6V1HaxAmdQJVvCVbi5Df7tR+GRzQPZeqOieidnfVfeqS7pDcmFLDc10LeQgjOMnkj4mhW2uaOdVp33XSVuvURUO4xwsH8k+aflSf1Lom4acubTS2y7CJ/FvY4+R9KhL129OkNva7yJcPaleSUDOaWXUDtxp1jp+ZZ9G6TukmU+nDK0RVkA+ucUyWMOFp0chGxTrZtJKc5+yvrlu7kcq5PwoW6OXzUGstLMXi7WuXbnlDauPIQULSoeJwfKjiZHcBSlRPjUE86UsOvddrVBKiVLZC8AYzW6tiOtJU7E7s8jkcVhjI7lOVvYwOMGu5nb1d2ZWEnjmmpVu6GtcZWtrNIbQkFFyjKB+TqathVY9G21xOqrI8y+0pCbhHJx/0ias5UiLkgSblDmr1pQIgV4Hf/m1AhaXAEhHB8TU7rCMiQYZcUQE95wPPO2ohiMcpSnIbHlRfNBPNYkxWwPxbYB8jXlr+EZuUhXaMcjMuECLY4TJSPUlxf8An16prkNId9mQlQUPPHFeTHbqW7cu1DqYKJUGEwWQf/tmj/nUaEanUhSu0tv+ckE24KRDjg8Hu0/sqQRyc+JrTj8IQkDwSBUhHTnFerx91gBXzhkuL3ud4kqQhc+NT8BB4xURCayRRJbopJHFNe6lEa0qatiCCKPJCkp0lbH1/wA2xeIBcz4AGQhIz/lKFCtqhHj3fOjyy2pm92S4aWluFlM5laWnQPebcx7qh8UqwofEVVZnejIHNXnCD2WQ0u5LZ0rcL1YtDfSVpiCYq03y5m5xQgqddZ9tkd4W/wCuAQ4Bg5HHmDRRaouoOp8pi5PmZZ9Jx3EvMMDczKuaknKVrIwptkHBCeCrHPHBHdHake07Ol3m7xy1DlPJj6gaQkn6LuaEJQXiPHuHUJQd3wSo/lKwzLtry1QlCy6ZU3e7/ISAxCirCw3u8FvLTkNo5zk8keANZ0vFc1u2wu1HS3c9fP5beKAtRNG4azujbfve06l07aW8HOfZMXBwD1wndn5H0piXNvbN4B4AoV6e6fM/UTU0y/bYGmfanXp5HuT71IyJDqD+i0graSRx+NUPzaLZ6y/JcfxwTgfKi4pNkqBxcBgbGOn8+yzw3NqRzipFL3u1Csq2qzmtoP4TkGpZaqTtQ0L7Mexk0PT5ISFEEVIzpPH1UL3WSRk58qmQMWf4lk6Wk2tSXNO7xrzi1uyjXXa9XCyFd7qRmKPiG1gAf2av/OmbdyiraBySfKqHdnOJ/LPtd22csbii9PzzznOwqP7qhceHZws8/stL/S4mfOyJj/paB8T/AML1oiMPBtkucJ2JzxjHFbd707C1LZJFsc7p0OIOwg4UhfkoHyINbKZcBadoVgfEVtxExCQthKR8RWMuivbqsUhfTPWqFpXS1ws/USaxEvOn07Pxqwn2tnHuOJz45HB+NKTVXbl6c25K0qjx3lg5GxQJP2Uz+pvRjRHVJsI1PALi0jaHEK2qx6ZoO0/2N+hFlc75WlRKUMY75ZVRRImBrhySRu/4QdIeKNK6KkyV+AJSSFGoqH2p+rOp5yZsfptcmnSDhUWMfeHlk4q5Nm6SdLLI2lFt0ZbGdnge4SSKImrTY4ydkWDFaA8NqAKY94cKXAEKlDmvO1FqQqFt0TcWkrGQZLwbGPlmopzp52otRuhdzvUW1oJ5TuUsgVeOazbV7UrebQfDggVrP2Fh0Du5CcH1NBLWnmjBxCqZauy/qi5bXNVdU7goKGVNxUBH1ZOaIo3Y86TOKS5fJNyu7iOf77kqIz8vCrATNPOJ/mSnI9DUI/abg24QW3DSUG8glJ1IT050B6PaeT/wXo22heMblNhR++ic6S09bEpTBscVpI8A20BWs77fGcGIjuAeeDWOVdpaRtaW42seIPjXE2uDVORoLSf5sFHwxXWXbFOKBCkmoq23uaRtekhJHA3jxqSRqFpHuPpSpQ/ORyKSgusrG9aXijaE5qPNlkqIBOwfLNESb1FWzlxCkn5V09utTqQC8En1JpugJweeqyaMjKhamsjS0Kyu5RefAfzqatBVctKtR3NTWdbckLCZ8cgZz/hE1Y2iRik17tSiL80lxUdShnbvx91RhGBhJxUpft5McJxj3s/dUZ7o5PjREIrA4wn8sjnxNeSvamaRc+0RrqfkHurqljGf6NptH+bivXHhaRjjNeQHWx9U/rVruQDlKtSXAZ9dshaR9wFTMFuuUDy+qiZjxHA9x6NJ+SG2lJHwqUhoSvBBFR8ZtKyD51P2uI2rGUA/VXpzjXNfPGzipS2wyvBoutdvBxkedR1ptiVEFO5PyNGdotLyVJLbufPCk1EllUiLHs2pG0W8ZHGKMLVCLSkrSPeHgR5VoW2DKZAJZbc+CVYP30RRQWgCuO8D8E5H21XSyi6VrDjFu6y3C0Sprw1BYltR7200GXe9TmPcWRk9xIT6cnascpJOOCoHNp7Sl6ucEwJkW16JsLhKnbRp9OZMnP5SXpW1ISk+aW0bj/SeVSUKVESQkvpGPXj9tT8J9KgNigR6g1WywtebV/j5s0bNB/6UohqFBtrFos8RuHAjNhDbLadoSkDgADwFRshIKSAK3wcpOK05CPOnxAMFKFlvMludzUeVbFYrhfOPGuKQQo+lfCOKltAIVFI4jYLSmPnYcnyoVur597nyoiuBwk/KhG7rwVfKrDHaspxeUhtIO1pcvo/Tt2nE8R4T7vjjwQTVWfwd9rVfO0M5dg3vMKG/I8M4CztJ++n510uQtvS7U0vwIgOIHP6Xu/vpbfgyLQWdVao1CjO9uO1D3Dy3Eq+/Bql9pnUWMHgV6N/SGP8Ax8qc9XNHwF/deiz5WgZShGPgKwPyi2yO7yFE+RxXZx95BCVYI+Na8mXGx+Mwj4+WaxGor2hq1HbjKaPvOunPhzXT+Us5lYS3KOR+ao1hmOvgp7ruXQeRzg1oPSXY6iqRbFDP5wGa7X0RANkRI1TK2jcylZPmOKxvasLXJaIPmAM0IuXpyO4Q2kbTzgjkVgXelOnKglB5OT50pcuDBSLH7va7w33U5IQc8bgQalIz0NhltllwKCBwd+Til79IqUAsNtuZ8ga+fSLragFQnkJ9UU0OXaEySlicCCuS1/XQrxrrJaciMf3nIcdc8g4fGgeNqFUdshqVIaJOffSTUjDvd0kK3ImxnsDOFDGRTtQTdJCll6lmRUpbkWMuuZ5OR9tYTe4kqQluVp5aVO8bgARX2NqCQAUz7aOM++g5FfWbnElErdiONHPgPCuvddSyv6ds0lrf3K2yOchXhWg/oxvZmHLUhQHmeDUoLhbmj7OiajIGSlSuR8Kzd9Dda7xTnuo5yFcfdSlNsoTFi1EwF9/Lj7E/knk5rTXFuqWl96y06Cedh5+qjJUyJKbBDqFt54IVUddJsKAEqdjKAUeVIPlSXSeCtLQj0hjWmn2lB1rfdIoIPgR3qat9VWtHXC0zNXWIRJIUo3GNgKTg8Op45q0tOYkeh/VaZi1Q0xHEo5Xuz6e7Wi0tTbY9qUN3qKlNROBsxspznf8AuoYu7M2atDLCy0yse+sH3k/KiIRXH76pUwwYUZSlJUB3mRtFeQesrzCumvNUPpcT3z17nO7c5zukLVn769foUNphvCWQEtHIKjlS/iT514OyLm/Yeo8q6XqSpuFJkPPq4UrBUSRkDJ8asOGOazIaX8rH1VbxVr34crWCyWuoDxpN2AAVZ8KL7OwDg/Kl7YtXaXuC0ezXuIpSvBCnAlX2Gmbp4sPqQtpxC0nGClQNeivmZIO4bXhH4WaJ1StI8xSNLJEylJ2+lHdoggbTtobsbScIGfSjy1NcJHyqsmfQVrjxBYp2p9P6cktRbq7J7xaC8QxDdf7tsEArX3aTtSCRycURQNTaUkzk2pnUdsXOUlKhGEtvvsKGUnZndyMY4oS1hbby7NROtWn7o5KbjFEOfapSEONuE5Lb7bhCHGiQk8hWMHw4NQ1oF8j3m6Iu0iCxdH5inY9vuFjW4l95DQ2KYk70pBKgMcKAqofOWuqlo4sKJ8QdfTz+ycYZAOS2FJPqMisiIUVat/dBKj5p4NJ1qFpu2dOV6z07qC4HUP0U4/JkquDin5D5R+N79tSiMpXn3SPcIwnAGKm+oGur3pSQmNbLhEaCILDpeltd42FuSENb1AKSSAkqVgKGceNP7Sm25AdiuDw1hvz25JsNR14AbmPI581bh9hr64zPwdr7TgHhvRgn6wcfdStidXLtbXHrRIj2e+zRLhRo8qBK9mjPe0IeVglwr2LQGFEp3KyFoORnFMnT91n3i2+2XCyvWx3cU9y4+07kD84KaUpJB+YPHgKRrrOyFkQviZbx/PqujipScF2CT/0TgV+3FYHJjLY2vJdaPops8fWMj76lD41id2jyBqW01sqKYNO6G5kiO8lXdSGlkDkJWCRQndvFRB9aL72xHdSQ6y2vH6SQaBrtCYCiWlONePDbigPszj7qtMa1i+MlgCRPatmqh9ILqlCsGS40x4+qv91TX4NKyCDoPUN5U0SZ88NhZHmgD9xpe9smQ7H0Jb7eZK1iXPHCsZ91JPlin32Fobdh6CW91vj6QkOyMfHdtz8fCsz7TSXNXgAvX/6VY/Z8F1j/AFPcfhQ+ytAssrwkHkDJNaklER87HQkg+GRUXIuq0tpCf0sq+VZWbkNnkSayGq16nppZ/oSCJKZiMpUn80Hg1lkhIGcD5VruXFtlIUpSRkfZUTPu724+zDeV8DPGa6wlDSVKKZjSFhSo7foSQDWuqFClL7sQ2VJHjlND0q4yIbzRKVgOqAI8Ug+ufKu8HVUZLshn2sOOsEJKW8qyT8cUl+C6yFJvWi1993KYHdqHgpFYnQ7EUWmHmnMfmu8c+lSFvvUWaj3ZLa1p5KScKrWlzXHyUPW1p1C1bSpOeB6ml6JA4hRrguziiXoTIbWMZQcgVGPpksO92I5+z94onYdgIuZjMsnCGQVDccJA9c0OLu7jLsdSHVrS82+6o7MjCMYwPrrqTg+1kakPRkBTinUYPJSrOK2m7w+N3dzFED9JIrSiXCPeXlxPZ1glIVtXlBP2VIyrTa0Re9cYdaDfips5P2Vw2Sk9CsftsaWrbIipdKvFSRzWL2VhpSltuuNoUOUgnH2V9jQLZOi5LzpSTgOAltQ+ysqrN3ODEuj5wMe+Quu5pbAWWIww22cOHB54JFact2VIIbylxKM7Tkkj7Kyw2FJW65NfDjaR4BopI+OUms223ulJiSEbleAPB/jXb8l1gc1l0K5Pa11p4ZbKDdYgORggF1INXGqqmjYL41hY3FJC8XKKSU54/Gpq1dFjBA3THuB5IY1q+tr2JKUr97vMlIzj8moNp6WtvBcPzFEGrkuKXCDZ/pM/2aGZ8lUBGCpG9Q8QfD50RCPNZH7omMktqG5ZGCAaqTrTsQ6E1Elam5LSnFZwZMcEjP8AWTg08NS6xS3LRYrS09IuUtKu7WlGW2z+m4cjCQfE+OPDJwKV/UTrtqPpRpSJEfv0PUd7bV+PVJiIQ24SeQAjBSkeA5z6k1HdmxRbXalR8OyMg0G15qpXVrsJ2fTJT7FIQX3TuQ3GeKiEjz2EZA+NJOb0E6jaWUpzTWpbhHLXvBCVqA+vBx91XVT2leiPUS8tSeqPS5+2zm46ku3e23AhbSEAqCQOF8ngJSVEk1P2hPQTXa2Y+jet022yZDCpDUPUcJLzaUBO87nVg4KUckd4CB44qfBlBw1MKgZGM+MmOVt+aobbtedpbRLgCZzd0abOMSWkq4H6po8sHbZ1hpxgq1z06SoIUE74ylIK/jhQxVuZfZ51BeY5m6eRo3V8VQyHrRcywpYPIwk96gnH9YUqtX9BJNt7wXzp7qe1EA+8LYZjWPUriKcIHzSKnMzpWj9RVTJwrCkJL4h9PotfR3b66J3JDSb81drK654h1gOoT81JP7qd+ku0H0P1gEpsHUyyOuK42OyQyr5YcxzVPbj0C0RqF9yJbpdmlPjILaXW0P59ChWx3P1ZoF1F2TvYF7o8abDWeRyoAf5Kxn+1RBmvdzUR/A8U7MJHzXpAvTujLgX7tEtNokuzm1NvSmmW1KeQocgrSMkEePNDf9zLSEVHcMQ3iFOtOKLr6nSQ2cobysn3B+j4V5zR+m/V7RbvtGk9c3aC4E8bXHWzj0y2VCi3SPX/ALUulLnFiXa9uXqEHA26H0NSlBPhkkZWKkx5UTjT27qqyfZ7LNux5PjY9Vde7dKWzGYY063aDGj31d7Rb58XdGUtyM6ytB2jONzxcBxwQPQUe6RjyLXYmLfJtsOC42VbmYilKZHOcp3cgH0qv+m+0rqJ24tW+76ZhuoUlJK2XVNLBxzkKyP2Uxj160NFATdZTsIkZO5O8D9Xn7qlMdCDYKpcnh3E2s0vZqrw3+QP2TMVI5x6VruyhyOKB4nWLppdgn2HXVm3L4ShyUlpZPptXg/dU+ma3IbDjLqFpUMhSSCCPUGrCIBw2NrI5nawOLZWkeYpdbo+FA8eVBt3WCTjjxoinOnBz6UJ3NwlZyeKtcZiw/F5tWyqR207iVO6btmc5Dz+PlhP76uF2eNOP2no7pKG0sgqtjSw0B4KWN32kmqSdrCQJvUq02vAUWoqE4x/SL/3V6L2l3+59oax22OhKbi9bmQ2rAywwEgAj0Ur18hWH9pH6sh1eNL6H/p3D2Hs/jjqQT8SSt36EdiK2Xy5NxARnu21b3MfLy+upK0M6aCgyszHk4wFLcSn9lL164yHSpwuEqPKlqVj7SajE9T9DWR/u7vri0RnBwU+1JUoH4hOazPbMZ+pbrQ9/IKxULQ2mbvH2JRJbCsch3d+6ta7dGZJKpllnJfLaMIZWNqj9fgTQZ0765dN5r7cSNr+0PleAlJkhJz6e9irAWeezMZQ9FfbdaWMhbawoH6xRY5Ypf0kFNcySP8AUCFUCIq/X2/3K0an09KsSLU6lLTMlwBySVggEAchIwc+uRTAhW5m2xExo4QAkY91Ixmm71X6Wad6jWRTs+G39IwUF2NJ5SoYGSkkYOCB9RqnVwn26A+7adB6l1Bd5yXChLFscLzSDn85xeUJHrTi3oEmq04rpa0zkMpKUJUnJ3j3Vj/FPzoet991HJkzrNAYivSrW4GpUiSspaSop3ISAnkqKSlRHluHrS4uNx6+2Ntt6fcbK8XVYjW9ZKpLp/QHdpAUfU+A8TxzW+db9TNItmXN6UvXhyaTMmu2+Y0k98eNoQvkhKEoSDnJx4V2mkiLLZqKVLdvEeXbktX1ahF7hteUlJHDgV+hjn1rNA05eH7osm5oZagRhEQhDW5OVe8rknnyoTsPUpbl4kalvfT+929LjCN7ZZSuQ0E5HvIBztz5ipq09ZNFSIa3zcrlGS44oqdNveKUEkkBRCSOBxS0utE7Xt9ncIkMtSUJTgyG07V/Ij+FbEO5R5sxUT2xIcOPczgEDx+uoCD1Q6byShEzXVoWrdkpcfS0rPyVjmoPT+s9Ojqo5pG3xGpDNyQ9Ih3iHcGHQ4pKUlbamQStO0q4VjBwRSELrvdMWUpsvssNhKiUlQBHFRUCS/cL1IhsoQplkN7yTgAknOPqoxjQ4qwSruytKBj3eR6nFZLTamYaX5QgIK5Tm9SkYOUjgfGuDVxPgo9NsYbeQptKh3+ScHgDyrPMsNu/LehhRHIIHOak5LrSZQQ3GWFBAI90pBHmM0O3C6SzHU7DmhQQslTYUdw+HIrtNLtSnNHW1CNWWZ1pMhtKLhHOCo4P4xPiKs1VRdD6mm/yysUOY7n2m7xQk7s+LyRjx4+yrdURq5DWtJzUJqMVoKlr3hGP8mlVqa8PoQWo34yU6cAeSfifhR/1Skrjt27u07lKLoA/UpWvQ5D8jv5Tu0H80etVnEMvQOxZz6q34Zhh7hM/l0Sy6oa0R08tYbgOJeuE8Hv5B8fkPgOeKqbqPTnVbq5IdkWC1yXGQo7pb6u6ZB9dx8cegqz/AF9VbrDAZk+wNvSlk7FLAVg4+NV81B1dvhhsQba8uOW0lDp3e79Q8qpWEg90LVAd2vFCTnSLT+krA+dUa5cmX7x7mG1hpBHluVyT9Qru51Mva7Wm1OWewXmOqI5FkruMBKZEpJXuSlb7e1e1O1AxnJ28nwwIXvWtncu8O23K8pEm4u90DgrIz4qIHIA8zQCjV9wemusMTrVJZaWpHexpYwcEjwXtJ8PIGrbEGRu5U+eMORwimO6dTvVvRGmUlTdr1Dab0q3ohu3W03NTgiqVg9ywlwBR90AZLnHIHrTWtXaX1ZpBMtuF1uS5ORa2fZrRe4qyww84pOFSFr3lK0p/NDmCojOMYqnETqMwnU1tj23TzF5uhdHcolMEtoV5HJx4eOfAYzRA9M6YfyjS5c412lxmJaHJrbExLiZUkp/GY3DeUFQx45xVxG5zhbgsxlY7IZCIzYV22+uOqb7aXpHV3o9ojWUFqAmWwuEhsvyCvGwobJWCFZUc5GAM1oWnUPZr1CmWqVp7XHTdUSIZkl6LLc9jbAIGNhKm85IAGznwqsNw03Z52pks3LqnGt8pb7T9ydeacZWwgoBTFTtylBQBtwCAD8qLJ8ftAT721Z7O4Xm7q4y2y2mS1KjMwUpy2twZJI25USRnjijAnnailifcHpbonXLiEaB65aavTjzPtDUK8wEMSFNbd24uMls+HPKDQ7qXsw6/LKn/AORUa7Rk5xIstyblII+DbuxR+WTSWvPUyFBuM22xOm8FTUzFijlDbkWdIUEoDroCf5vvCM4xjBKR508ujWkb3epl1ndPtUaksw0/BMMy3pQdhNzVIAU2hIx3nd8jPrSOn7MW47JY4HSu0sG6Ud86ZzdMukToV4sjoI2pmw34w+3Bb+uhu59N5OoEqP0uzNKvFTboUfqKCP2GrE2Prh1k0hf0WjVmv9P3i2QUupkNXVKUOTyhteEoWsbUqWvuxyoADJrlt6n2nW8yFG6odlq3BExZ3XGz5S223ye+DiAUqSACSdw8POiRZIc3U07JJYHxOLHiiqaaj6AXV8Od3MlBQ/mgte8D5AhP76DI+ger2hHi/prV10t5T7wMWU9HyfjghJ++r1Mz+ybquR7PYde6x0i6t/2dIloMhnduCQNh3FKSSMEgA5qQndnGTOuEm2aP6taJ1BIiOKachPvJYlIUDgpVtVwcjH5NEZMAdV0UN7e0bpeLH7qllu7QHag0khAm3d27xk8BM2Kh4Ef4yQFn7aJrZ229TMqDWrdBMLP5zkZ1TP8AYWD/AOKroaA7HkN6PIn9WbFie08RGbiSSpDaf094Azn0NZdSdiPp9ed/0fPkRyrO1MllDyefiRmpkPFp4T3Xn6rP5/snwbiAqfHb7hpP/wA0vPeXrGB1j662S6xIT8dibMhx0tPY3JwoZ8OMZJr0a7QepIXT+DG1jeVKFt+h46o+3/CKSjZ3afjuGPrpLROyUjpN1Jsl7k2uFIt6Xi6mfHSRtUkZ2lB8FHjFXBvfRzRfaX6GDQ2p1OsORHFiLLaGHYrw5SoA/lDnkeBqtzpTmOJcdyr/AIZhw8OgZjQCmNAA8gvJfqZ2hNedQ5brCbi5b7XuPdQ46ilIT/WP5x+dLZCpb7n4xxSyo+JNWH61dhbrj0fnyHWdOvaksyVEtXC1tl3KP67Y99J+oj41X+VbrhAkKjTYr8Z5HCm3UFCh8waEzGZGNgrIzv5A7IhsLT0ZxDiXVpUPAhR4qxPRvtE9SumExp21agkPxEqHeQ5Cy40tPmMHw+qqtQ2rnIdSxBblOvKOEoaClKJ+AFPrpD2e+uGrpDM25WRdjsJILtxvCCwEo89iD76z6DGPjQ5sWOUd4e/qPeixZc0RoHbwO4Xqr0l666d6q9P3dVxVojPQ0FE6MpWe6cxwPkfKl7F6J6QhhQtFlFtU6oqcXCecjlwkkkrLahuOT50s9IWqxaCgWvQ+j1vLhSZjUm6THeHJqkEE5H5qAAcJp4Suo0NlY2N+I8fKo8Rcxul5uuv86ocwaX3GKB6LTtfSuxWhSnI8Bpp1z+cdAJcc8/fWTuV9ZNEEfS9sYyoo5+GBmkh1M6zX9u6pg6eubkNDCfxhbA95R+dDMLr5r6LhqRcGpaMch1sA/aKjO4hCx2k35qS3hsz2am0rET9OQpJcehd3ElI4ZeDYUBngpUn85JHiPsxSl1lo+dYpLt/sGnJNpu4HvSLaPaYMzn8h1nhWD+ltBHqa1LV2jMthu621Tbn5zjR3J+yiW0daLJfJiLewlxRWMqU6Q2kD4ZPJ+FSI82F+zXKNJhTxblqUsbrxorqNe/7mWrNFxbPqpB7t/wCl2EpYSP0mt3LhI8B9ppjWbop070m+1dtOaThxZjYBXNTuQ4vPBJIOOfTFbOvOivTDqrLaueqbWh6VG2qZkMrLbiAORhSeaMrPa3rXbGLbHUl+Oz7qEPLKlbAMjKvOpAIPJR9Onmtm1aUgIiqfStxS3clQKiRyfic1vslppSYrC0JQxwpGOR8M1txloZYC1pKFEkqSDxzXwpjgE5BVyefOlXKNccmIdkLK17Ad6SsAp2+gx++he/uywovGCgIWQSsnii+btYjlSXPeUOBj7qiphbSnu3GirYndyPP0FId04UFG9OGYcjWFlUu3uNranR1hxONu7vAME4+VWxqs2ioz7Orba48HAHJ8baFKBA/GpNWZpzRSQG0A9U3VNG2HI24fJz/1dKK/agZjw3n2/eLYJzmmp1iSpxu1spWEBff7lHyHuVW/rReW7BpZceC6PaZB27gfAedZziJ/yHDy+gWs4W3/AB2nz+pSD6r9QXb3d3ojklS22lEJzyAfhVauo/USDYH3oSWw6lkhclSgQkgjIbSQR7yvnwMmifqJrKHa3x77jrylH3WhuUVH5eVV8laW6mar1ZcHLHBnPsSJG9PfjLRB8OFe6cfKpHDoGl2t+wROJZMjI9MXM7bLvD1HpW4KmZ0uLS9JaJcuUCe457I0fEbHd2SeAcLBOcDzFQ9o01L1JJTE0+uXOuG0Nw23YZaCU8+8SkqSD6ZPnnyFWF0t2d7ezaYytbIirWSlbjUdOwOLGfyscEfAYoxt16gacdai2uC1GjNODclpAQCgHzA+FWEvEo2nTELVZjcGln3lNfVI/pxoPqP0+kv6qu1mnxmoDW1ENpfemY4oEe+kE+4M5Vkc+HnRnoK82lrUqdRXnTFqkQLM37bOlqt/sao6jkJS2GyEreKyA3uB973j7qVEOTrX1Us/0BCTYVRVaha/4uDagHWyoYUpHIxwTS30tctdQLbPv2tIU2bpiD3bjkO5tB/2+YpJS2gKIKhjKlFQPuoCvM1JglMzdRFKtzsX8LLoBtaei9P9MtSaxt9uujGooLUtz25xj25q4RlgJKt76hsU2gc7uFKxn1podD+kUDqx1WSXte2jUFsjyV3C4KgplRZQZSNrbIDgSO63Y/JzwPHmoTSOnZD9oflXjpkLVp2/QgqZqG2d6wiPHSCpaB3mQeQAQCN3AzirQ9jLppatKaUumurY5cnWLwER4QuTKEOoYbzggI4wSc58ably9jESDulwcYzTAOGyG+u8PVNgujS9Jy40RUNofRqn46HW2dicbSFgjHxPPmDTd6LXGJK7PUK4xYEKMhwugrhRwy1IWlWHHUpHkpW7B88Z4qL6naLl64nKjsvpZSyeXFAnGfHFFqbhZrToNGlIbzYTbYYQdqAhKlY5ISOBk5rNjKeYnMkNm9lrH4sTZY3RNo1uqTa2Qbr1Bj2VqCxONwmOZQ82FjaPPBqM6t6b1vp29RkdP5Mn21EZuDsQ9sEdk85bGQEbSTnHkc0wdG2dhPXhq7XwBEKPHfU2tRwAo8/sxUR1luzZu705p/aFyUobUnzGaNBkOhkbXKkPLxY8lrmvHvSq1N1k1Po/UUGM7b4dwcsDTTLcu6Whp5+dLSdxf7xxsqKQrwwoHGOc81kv2udEaXg2y36k0fcY14vKPpW+RbRdlMtslxW9kKS+h3DpbIWrkY3pHBBxk6lXLVrC7Ii1Xu4/R5bdy0wrKGnMpO9SR+V9hob1ZfPYoNti610hb77qm7A3ObIlIVHeZjLH4pBLZSCtQBWSoEgFNaOGQTMD1kMnH7CUx+CZtj68an1FqbZ006zagsM26usxrdb7u0+Y7GMJQ2n2dTqXM8DK2wOc16HaZZ1PH0xaYGs7uxdb7GjIRPmtMpbS+9j3lAADjPhwKpd2MunmktXX0dSpGmJ1vXYCY8Bp+WmQytzGCpJ2JPu5OByBmrk6ovCrFp6bcmG+8fbZV3Le7G9zHuj7ae4hR9ICAtb6ifu+rhpiOln2W3oSpxS+Ct9XkPgB+2m30qjzbUhaNo7h8ZWBwAryIpFaP0s7dJQk3C5P+2uq3vOLByo+dWF03abnbITbTElDiQAeaC072n9EZTAFoJIzmgXU2ntPzklVwsNslHyL8NtZ+8UWoekuslLycEDyqAugKgUqyTmjhyYdkLw9CMuWx+Vp2y22M43wAxEaaJOPIgClXqTvnkKj3QPqeaKgcueB9CPA1YbTjioYe2k92tCsjyBAzVWetOvWoN6lW+3oKpj6lEKxwkeG6gS7hEjslRVtnQmJ7zpktrfYHdoaSoEpyeeKmrpemY9udeW4QW0biFYOfTjypSWi1OPLXKmoC1rVuLihlWfXNZNRTFMluBFfcUpYG4biQfQc1BlJjYXKbDGJHgLQnTHZTzkt/JLqifrqOUtQUVmmrG62dCemkhjQerlsxrozHbclOPQt6VKWkHlWD60TQNVdmPW6R7DetNLW4PyUvhhQ+oEVD/KpHt1B26njirG93SUgSsqORW3FXtwBViG+hPTG+p7y0XRxKVDgxpSXUj9v7a1pHZcAQVWjUmV/mpfZx94NBfw3IbuBaOzieO7maSks2qr7a3AqDdZDPwSs4+zwo1t3VC//AIlM4ty0tq3c+4o/WKDLlYZNg1BJ01ckJbnRFhKkA5yD4EeoNSupLT/Iy7xrLdH09/JbQ82cEAhQyPH7Kg9pkRXpJFKU6OCWtQBtN2D1ntTyUJuNpkMKBHvMqS4nHrg4x99SKuo2n56nGIs5LS1jCFPAN4z/AI3FJgQy4AvJ8PKsDrOwEDPpR4+L5DNnUVFfwmB/6bCsQiQpcJD4ntStqCQUlOVffioec3IUhR7wuJOShK08oV9gz9tIhiZNgOd7HkuNBHJCTgED1HgaMtEawuF2bl29t4ctkpWpZ9wnxwPAAfCrjDzhlA7UQqnMw/wpABu03tDTX5V8szq23Un6RjoIU2fDvE8+eP8A/c1Zaqv6Ht8i1XvTrKZm9oz4u4IQBlZdTk58TmrQVZBQQkx2hUTn5+l4kVbiW3fbO92/DuMZ+01W7tCqgWqzw7V3hclSDvIzkpHxqz3XmTKjGxeyJTvV7V7xGSn+a8Kr3qHRf09JM24qU+4fzlnOB6VDk4HJmSGdp2P22Vtjcchw4hC8bj7m1V2LonT0Z5U9dt9pfWdxUoZx9dYriuU3J2QIHszaOMJTzVjk9O4bRIDQx8qg9Q6AQ+ypMSMELwRv8x8qePZ+V3Mox9pMZvIKt+pdbWawxENXa5JD6eQyg7nM/IeH10FhvXOv+8jaDsobW9wmTKPhn0SPD76b157PFvlXBUx9ta3FqyVq5OaaPSzpzG00tHs6lJUkjOMUp4T+F3O6G/j/AG4/tmlTGb2T+tUWYL5frNJuah73eNK34PoAcH7BUzpuP1OsmorZp1lm+Rn5MpplENSF++VLCcBCuM848POvUPT7CnmUNGOlwHA8KOLZpLThdZlyLNHVIY/GNuFsBSFY8QQPGjufpbyVYx3aSjV1KWXWq6wf5Cr0Qu1o9jkxkQ2o6UDABASBgUbaR0hE0joW06Xt6ChmDEbaAJ5zjn761rtotrU2s4ciWlfs9vV7RsI91ah+SD9dGt0bKYpSkYKvdz6VmQXyFzneK2MzomRxxxjcc0AasWxbbQtUVtK5JG3j9ppKoRdHXroJgUEbMpOKd15htd0tgp4SNw+JpXXNa03J2IrhtxHvD1qHIaNKVjk6bKrz1Vdft0+G7FP411WTg492hzV0d66C1POs7UN+8sH87jiinqbblN6uajDcqOANpJyBk+FQPUGY4XIkFghKYrYzt8SaPHvQQ5TVpY9VbHerrL09E068y0+486gFyYiPjds5ytSc4x5c1Ha30xq3XWvrJoSHb7i4za0os8SdKjrBmEEl6SXCMKSVZI5OEhNSOv8ApxrPqMuzO6UhiYuD3ntDAeS2sglPKdxwTgGnt2SOkmqdJyLpd9XNT4heUGWIMh7cEtDkrIB25UQAPgFeua0mIdMAtZHiBvIcrH9JdF2zp/pC2aatTIbaiMpSTjlavzlH4k81r63u8q+aij2WI2+qHC5cdbGUl7zz5ccj7fI0QzrzGslscmOYyBtbT5lXlWtoaCmY404ptZU6reogedGvUVAKNtBaQQ22iY4CQAFZKv3UwksJaKCFjaRgJIrpaYyGGEIbAAAx4VJoBGNzRIHwBp4FLrWkQ02SlSlI+IPH31E3KH3qVbJKkqPCVEZqffixZCilSVD4pJBrUftqm/dZWrBPGU5rkux5oNhq1JZWZ8V19qbGlAd2g+4ptXmQfl5UhepPRS46ouf05Gl9w40jb3TjZKfHJ94Zq0LlukoSpS2ozmPDCCDUPKhJ/m/ZSxu8VAbxTXN1JwOk2FUVrSOobJITCmEPpI4Uyd+B6EeIqXtvS5dwv0RTyCtTjyM58hmn9fdNQJEV1b/cqwDhQRg5+sUC2i2XGzTpNxM7vIkCO/JJI5ASgkc1S5zy6ePHb4q3whphfN4BeZvaSuQufWzVb7atzTVwcYbP9VHugfdSzUpWfdJBBqb1fc3bzqe63V5W5cua86T67lk1Bq4rQg9Aqg81I23WurLG6lyzakucNSPDuZS0j7AaY+k+1r2g9NSGWrf1GuLzZUEBqSoOp548FCk6r8onHjUzoq2KvWsrFaUjJl3GOxj13OAfvp9BNKv1qC6zrz1gjzLu6FyQi3iSoJ25X3aSvgeHOaJu2OERdT6flMpIUphICh6Y4/ZQpLzM6wXl5HKUT9gPwQAP3Uc9s2L3to0vd0p5CUJKvu/fWX1CQTBXm7DCUJ6OnyLjaG1uqKlIGCT51IStzPOMkjNDfTuSTZ9oPn5UQy3FqSQcn5+VULhRKuW8lB3Rx1cZbaVe88Q0P8ogfsJpk9NdKSYtnfnvssOpUSEpGQop8zml0iKzcrtBgvOONgul3KDj8kYx/a+6rF2yKi2WuNChPkhtABxjP11pOERVFr8VnuKyapdPgtvTkluPq3T0dTbzRVcYyBgZCvxqfPyFWcqtdhYVJ1bZFlpJCblFX8UkOpOfuqylXIVWEouvz4ZNhycZ9q/0VKdU1JHhTO7RQUV6cA8/a/8AQ0pg2Qn51o8Ft47ff9VSZh/vu930C+uzEYxjFRs2ShQI4rLLSQMA1DyyU5GamtjChF1bKJuqkjJSKj7be0QJjYkObGyobjjwFbFydwk8UI3R0+vrQZYGvFFEilLCrNaT1XYvZWlRH0KAAySeTTK09Oi3Npx1tQIGPOqCtX+62xe6HKWgDyzxTS6R9dJdluqLdfXj7NJIb3k/knyP21n8zAc1h07q8wclvaDVsrfCC2hReQACfGtGe3vyTyBWCxaji3iKHGH0uJV4EGphdvckt4bTkHzrNtjL+60brTmYRnU5LLUKu5nKB4TtzSc1PLKb+oLO0Kb4+2rK3TRMKYS5MdcJIwQk4oO1L0x0rMBffhkuITtCt5GBSjgWRLvYCKOP40I0kEqk/UaTMh6lkRZA3MPgONKPy8jS/nS3JMlbj6ipR8zVouq/R+1To/fRXnWnI59w7s8enNVo1Tpy56fmhqU2VNrOUODwPw+dPk4VPht1SCx4hdFxeDNdpjO/gVH6WuPUdjqHZWNHttm2KWPpFS0hQCc+HrnH7au5YYi4sFCpH88777h+PkPqHFV56Hwkmcp7YM5GTjzp0dQtXs6O0s7MLmZDye5jpAySsj0qZEO4KVNlu1TErTv10/lHfxbYikuxIBw4PEKc/wB1NXREFu2x2j3am1HAG01WzpzEfjO+1iY44/IX3ziSsjeT8FY/bVldF3CbLUxbkw194spQCfe8fvqQ1RiE3bM09JbSvJKQOSR51LiOoDAJHyrYgxEQIjcdAztHvH1Nd1HJ8KIAmEWo93e2c4yK13Z6Gz76Dg8ZrdkfkkVFSkp7tSleVKQkXddxhrBAcGBwTWm87a5KSkOg/EK5FJE9SYT+q7l9Gyj3TUgoKFK91e3jOPjimnY3bVcrZ9LRvdG3JAPgfShF4AJKI1lnZQms1tR8R4qspxkq8yaWPU68DTPRzXF+UvYpu1OMoVnHvLGB+2jbUUsvSVLweTxSM7Zd8+guzhLioVsdvdwaj/EpHJH3VnsInJ4hrP7rQZDRBhaAvM98FSypRyScmtdZrZeB3HitdSRWpWeWs6jcfGmH2c7b9KdctExdu4C8R3lD+q2refuSaXrhxmnP2P4PtPXW0y8ZFthTpys+QRHWM/aoU891tlJV7KzGln13DXdym/ld7OfV9W801+1lHMvpJp+6hOe62ZP2fwpRdLFGRdXJJHK3Fr+0k07+vzBuXZ2ju4yY+Dn5ZFZHEdqklHiFossUyIjxSI6XPhy3raCjkHNGstlZThI8qWfSqXuBSk/m0yn3XA2X1H3UDJqqnFOKs2HurX0XIiO60MZ5Ta1MFtBSVcgn3v3in6uZaAnC0KaxxkedVj6WWld41PLvb7agp15x1vac5AOB9wpzquVwit7FrC0ngJcR++tdhs7KFrVlMx/aSucmHpdMJ7VdkdjTl4FwjHbnx/Gp4qy1VA0NdA5rDTrbsMtLN1iDKHODl5PlVv6mBRQlL15ZS6uwlX5vtX+ipUSO6Qj5U0O0LPbgosRcUBv9qxz6d1/GkW9eu/VtQfE+taPh4Jgb7/qqPNIEzvd9At2SpC/DFQc8EFRxUmxlwZIPNaN1TtSflVgBSiITuzwAIzQnOWHCQTU3e5G1SgM0KPyhuJVXOXNC13mSonA4qOlNqSeOKmWHUOkDNY5sLcCQKjvZqCOx29FNvs89S5Ea7s6Zu8sqZXw2pZ8fhVzbfKaeYSpsjGPKvMeFKk2ue1NjLLbzCwtKhV2ehvUdvVOn2i+5l5HurGeQaqn4jIyXMHNWYynvAa48k3JQCgrxocuzCVoUNueORRGpW9GcVB3ApCHMKBNIzZNfvulfqmxfSDL2MHAOQPKq3dQNNifClwUthTrJKmsj84Va+UUNyHS4sDePOkhrK0ttyZUtCwUlW7x9aluYJWFrhso7JDDIHt5hAHRWzvwrcZEtvYvcd2fLFQWtrrN6ha2bjWyQBb7U53afe4UvJyamdY6tOmdIvsWtrdOuCiwztHhkcmoDQ8tmDFaYnQkoeHvLKuCSfHms6+MxOLD0V0yTtwH+KZVhgzbelqM4WHE8A70Aj7asz0Y02G4xvctgIUB3bQByknzIqtdsuDd1fixYby0uOrSgAc8k4FXP0zAas9ihW1vBLDKUqP6Sscn7aRqc4VspckeBrC4oA8GuxXnxrE4RjijBBJWCQTilb11161oHQU64d8G5MoeyxvXevjP1DJpmSHFVTLtQ68i6l6jRNHR56ER7Mjc8nPi6r1+Qpr3aQnMbblp9P5NpnwVSX5CHyMAq2YUD5kmnzpZ5qFp49y7+Ld5Tk0hdH6fj3DuYcJ0B54gEoO3P2U9XoLdrtzFvZJ2MNBOT5n1qk4hNoirqVbYOOJJNR6KPmv8AevEk8eVJDtxdO+pOstCaTtWi9KTrtHjOOS5aoyCsoJGE5A8fE04CpfeZJ4zTZb15o6NboqJl0ZjqDaUqS7xg4qPwN7Gyue47qVxYO7NoaF4i3zQesrAtTd60vdIShwQ9FWnH2iht1hbZKVpUkg+BGK923JGiNRslK3LXOQrjasIWDn4GgbUXZ36K6qKzc9BWd4rPK22UoOfmnFajU07rO2R0Xim61T97HUYsan1hqAj/AIt0vKwr0U4pKR++rv6m/B7dBL4hRgW+da3FchUeQcD6jQFd+y3YezV0/wBaX60aikTheorMIIfSAUDvPIjxzmmzODInb9Cns7zw0Id6NR0++4rkhA5p99QGDc+ztc2UjJYBPPlhVInpCCm3uujg5ApgdTOtei+m/RybatUPue0XVa2I7Tadx5A94+grJcPP+S4eIK0nEBWO1w6EKv8A0meSmWlgqOSnH2U0NSzPZrLMcQraoNKCfgo8Ck30suTT1ybfjK3NuElB9QfCmhqTbco8a1F0tmU8ASPMDmgGPtMkM/dG16YS79lPdGNKzYjSnA/s7tCeUk8k+NM59cpClMusd5nxKk4P21odO9I3ayWNEqNN7/vyFgfADAqdkzrjFcK7hAWQk8qCcjFa1vJZd51G130E4yvWdiQQMpusXGef8MmrfVVPRlys7+srEA2htxdyjbco25V3qcVaynhMSX7Rugdba4OnRo+0GcIXtftWJLTWzf3Oz+cUnOdqvDPh8qWtp6EdTmsGZpvYR/8AOxz+xyrZVyrCHiMsEYjaBQ8/VQ5cKOZ5e4mz/PBVrT0c1+22AnT+T/8AVMf69Q916LdVH8iPpfeMf/Gxx+1yrWVyifms3Oh8/VM/L4vE/L0VHrt2dOtspSizordn/nKIP2u1Au9l3ru4D/6i/wD7OH/tav8A1yu/NpvAfP1XDh8Q6n+e5efbXZd6+NLGNB8eZ+lIX+2qWb7M/W1TOHdE4UP+con+1q91cpBxSYdB8/VOOBEep/nuXn7P7K3XN05Z0Pn/APJwx/paYfRDoz1r0NcnRe9HLYjOEEKFxiLH2JdJq39cobs+R2xA+fqnDDYOpQuxa7w42lMiNsO0bgHEnn6jWhfLJfhEWm12sPOHy71CSfrUoUb1ygDIcDdBFMDSKVUNWdPu0Ldbk6q3aRWmPyEH6SiDj5d7mvuhOgnU1dwdka1tAaZ7tSUoVMZc3E+H5KzVrq5Uj8wkqqHz9UL8FHd2VR68dmTq3PkPY0Yhxpl9Tkf/AIQjJyMnBH4zjj1qQ/8AR06nXBhtE3QKo7iBjd9IRFfeHaujXKhzPM7tTlJiaIRpaqg6O7OnUyy6ihT5liAjx3e8J9sYOMeHAWasnZYOoWmEonwShaeM96g5+w0V1yhgUnucXblRaYks/lM4/wAoV8VClH/B/eKla5TrTaQveoF7RbpTltt5kyUtqLLQcQncrHAyogDn1NU1a7LPWe76hnaj1DpImROfW8sKuMRR5PAyHfKr5VymObr5pzTpVR9I9njqLpy6NXZrTwbdjnc0lU5kpz8QFmnDH0DfrnFSm92hMd4jCiy8gj/xU165QX40cmzkZuTIz9JpJO5dF74EldrfST+g6pPP15oSvXRbX90SY8jTbb6RwFCWzj71g1ZmuVCfwfGebFjy/wClKZxSdnOj5qn0js4dREpUYGnpEdXkWrkwk/8AmVkgdG+0bbUbYUuclKTkIcnxlA/95Vva5T2cMZH+mR3xHoufxF0n6mN+B9VVyJp/tYW1WBYoM9H/ACkuMkn/ALyl91R6Q9rvqypi13rTFvhWdh0OFlm4xSXFDwJ/GeA9KvJXKP8AhCRRkd8vRRxkhrtQY2/f6qkel+zL1a03b0xUaVLizys+3xfH/tKiOoXY8131IYjxdSaCMlqMoqQPpKMnBPydq+dcqKOEQh2oOcD5j0Uo8UlIotFe/wBVQey9jnXunGmm7R0/7vuRtSfpKLnH1u12l9l/rpL1DCkp0f3MWOk5WbnExkn0DufD4VfauUWLhsUTxICSfd6IcnEZZGaCAB7/AFVebZ006k2q2R4DWm21dygJOJbHJ/XrFI0H1WWSk6LC0n0nRv3uVYuuVPpQOtqv+numWtGtRWe43HSBZbiT477jhlR1d2lLiVFWErJOAM4HNWArlcpVy//Z"

# ── CSS ─────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

html,body,[class*="css"]{ font-family:'Inter',sans-serif!important; background:#0d1b2a!important; color:#e2e8f0; }
.main .block-container{ padding:0 2rem 2rem 2rem; max-width:1300px; }

/* Sidebar */
section[data-testid="stSidebar"]{ background:linear-gradient(180deg,#0a1628,#0d1b2a)!important; border-right:1px solid #1e3a5f; }
div[role="radiogroup"] label{ display:flex;align-items:center;padding:.48rem 1rem;border-radius:7px;margin:2px 0;color:#7fa8c9!important;font-size:.88rem;font-weight:500;transition:all .15s;cursor:pointer; }
div[role="radiogroup"] label:hover{ background:rgba(59,130,246,.12);color:#e2e8f0!important; }

/* Buttons */
.stButton>button{ background:linear-gradient(135deg,#1d4ed8,#2563eb)!important;color:#fff!important;border:none!important;border-radius:8px!important;font-weight:600!important;font-family:'Inter',sans-serif!important;padding:.55rem 1.4rem!important;box-shadow:0 4px 14px rgba(37,99,235,.3)!important;transition:all .2s!important; }
.stButton>button:hover{ background:linear-gradient(135deg,#2563eb,#3b82f6)!important;transform:translateY(-1px)!important; }

/* Inputs */
.stTextInput input,.stTextArea textarea{ background:#0f2236!important;border:1px solid #1e3a5f!important;border-radius:8px!important;color:#e2e8f0!important;font-family:'Inter',sans-serif!important; }
.stTextInput input:focus,.stTextArea textarea:focus{ border-color:#3b82f6!important;box-shadow:0 0 0 3px rgba(59,130,246,.15)!important; }
div[data-baseweb="select"]>div{ background:#0f2236!important;border:1px solid #1e3a5f!important;border-radius:8px!important;color:#e2e8f0!important; }
div[data-baseweb="select"] *{ color:#e2e8f0!important; }
div[data-baseweb="popover"]{ background:#0f2236!important;border:1px solid #1e3a5f!important; }
li[role="option"]{ background:#0f2236!important;color:#e2e8f0!important; }
li[role="option"]:hover{ background:#1e3a5f!important; }

/* Slider */
.stSlider>div>div>div>div{ background:#3b82f6!important; }
.stSlider [data-testid="stThumbValue"]{ color:#60a5fa!important; }

/* Checkbox */
.stCheckbox label{ color:#94a3b8!important;font-size:.88rem!important; }

/* Radio */
.stRadio label{ color:#94a3b8!important;font-size:.88rem!important; }
.stRadio [data-testid="stMarkdownContainer"] p{ color:#94a3b8!important; }

/* Metrics */
[data-testid="stMetric"]{ background:#0f2236!important;border:1px solid #1e3a5f!important;border-radius:10px!important;padding:1rem!important; }
[data-testid="stMetricLabel"]{ color:#7fa8c9!important;font-size:.75rem!important;text-transform:uppercase;letter-spacing:.06em; }
[data-testid="stMetricValue"]{ color:#e2e8f0!important;font-weight:700!important;font-size:1.5rem!important; }

/* Progress */
.stProgress>div>div{ background:#3b82f6!important; }

/* Hide form container border/background */
[data-testid="stForm"]{ background:transparent!important;border:none!important;padding:0!important; }

/* Tabs */
.stTabs [data-baseweb="tab-list"]{ background:#0f2236!important;border-radius:10px;padding:4px;border:1px solid #1e3a5f; }
.stTabs [data-baseweb="tab"]{ color:#7fa8c9!important;border-radius:7px!important;font-weight:500; }
.stTabs [aria-selected="true"]{ background:#1d4ed8!important;color:#fff!important; }
.stTabs [data-baseweb="tab-panel"]{ padding-top:1rem!important; }

/* Expander */
.streamlit-expanderHeader{ background:#0f2236!important;border:1px solid #1e3a5f!important;border-radius:8px!important;color:#94a3b8!important; }
.streamlit-expanderContent{ background:#0a1628!important;border:1px solid #1e3a5f!important;border-top:none!important; }

#MainMenu,footer{ visibility:hidden; }
header[data-testid="stHeader"]{ background:transparent; }
[data-testid="stToolbar"]{ display:none!important; }
.stDeployButton{ display:none!important; }
button[kind="header"]{ display:none!important; }

/* ── Custom components ── */
.result-banner{ border-radius:12px;padding:1.2rem 1.8rem;margin:1rem 0;display:flex;align-items:center;gap:1rem;font-weight:700;font-size:1.05rem; }
.banner-CRITICAL{ background:linear-gradient(135deg,rgba(239,68,68,.12),rgba(239,68,68,.04));border:1px solid rgba(239,68,68,.35);color:#ef4444; }
.banner-HIGH    { background:linear-gradient(135deg,rgba(245,158,11,.12),rgba(245,158,11,.04));border:1px solid rgba(245,158,11,.35);color:#f59e0b; }
.banner-MEDIUM  { background:linear-gradient(135deg,rgba(234,179,8,.1),rgba(234,179,8,.04)); border:1px solid rgba(234,179,8,.35); color:#eab308; }
.banner-LOW     { background:linear-gradient(135deg,rgba(34,197,94,.1),rgba(34,197,94,.04)); border:1px solid rgba(34,197,94,.35); color:#22c55e; }
.banner-SAFE    { background:linear-gradient(135deg,rgba(34,197,94,.1),rgba(34,197,94,.04)); border:1px solid rgba(34,197,94,.35); color:#22c55e; }

.info-card{ background:#0f2236;border:1px solid #1e3a5f;border-radius:12px;padding:1.2rem 1.5rem;margin:4px 0;transition:border-color .2s; }
.info-card:hover{ border-color:#3b82f6; }
.stack-card{ background:#0f2236;border:1px solid #1e3a5f;border-radius:12px;padding:1.3rem 1.5rem; }
.stack-card .lbl{ font-size:.7rem;color:#7fa8c9;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.35rem; }
.stack-card .val{ font-size:1.05rem;font-weight:700;color:#e2e8f0; }

.step-card{ background:#0f2236;border:1px solid #1e3a5f;border-radius:12px;padding:1.5rem;margin-bottom:1rem; }
.step-title{ font-size:1rem;font-weight:700;color:#e2e8f0;margin-bottom:.2rem; }
.step-sub{ font-size:.82rem;color:#7fa8c9;margin-bottom:1rem; }

.rule-item{ display:flex;align-items:center;gap:10px;padding:.48rem 1rem;margin:3px 0;background:#0f2236;border-radius:8px;border-left:3px solid #1e3a5f; }
.rule-item.CRITICAL{ border-left-color:#ef4444; }
.rule-item.HIGH    { border-left-color:#f59e0b; }
.rule-item.MEDIUM  { border-left-color:#eab308; }
.rule-item.LOW     { border-left-color:#22c55e; }
.r-id  { font-family:'JetBrains Mono',monospace;color:#60a5fa;font-size:.8rem;font-weight:600;min-width:40px; }
.r-desc{ flex:1;color:#94a3b8;font-size:.84rem; }
.r-sev { font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.75rem;white-space:nowrap; }

.score-row{ display:flex;align-items:center;gap:1rem;padding:.65rem 1rem;background:#0f2236;border-radius:8px;margin:3px 0;border:1px solid #1e3a5f; }
.s-lbl{ min-width:145px;font-weight:600;font-size:.85rem;color:#94a3b8; }
.s-pill{ padding:3px 10px;border-radius:6px;font-weight:700;font-size:.75rem;min-width:100px;text-align:center;font-family:'JetBrains Mono',monospace; }

.rec-s{ background:#0f2236;border:1px solid #1e3a5f;border-left:3px solid #3b82f6;border-radius:8px;padding:.65rem 1.1rem;margin:3px 0;font-size:.85rem;color:#94a3b8;position:relative;padding-left:1.6rem; }
.rec-s::before{ content:"";position:absolute;left:.75rem;top:50%;transform:translateY(-50%);width:6px;height:6px;background:#3b82f6;border-radius:50%; }
.rec-g{ background:#0a1628;border:1px solid #1e2d3d;border-left:3px solid #1e3a5f;border-radius:8px;padding:.65rem 1.1rem;margin:3px 0;font-size:.85rem;color:#7fa8c9;position:relative;padding-left:1.6rem; }
.rec-g::before{ content:"";position:absolute;left:.75rem;top:50%;transform:translateY(-50%);width:6px;height:6px;background:#1e3a5f;border-radius:50%; }

.disclaimer{ background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.22);border-radius:10px;padding:.9rem 1.3rem;color:#7fa8c9;font-size:.83rem;margin:1rem 0; }

.sec-lbl{ font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:#3b82f6;margin:1.5rem 0 .6rem 0;padding-bottom:.35rem;border-bottom:1px solid #1e3a5f; }

.mono-rpt{ font-family:'JetBrains Mono',monospace;font-size:.78rem;background:#0a1628;border:1px solid #1e3a5f;border-radius:10px;padding:1.3rem;white-space:pre-wrap;color:#94a3b8;max-height:500px;overflow-y:auto;line-height:1.7; }

.kb-row{ display:flex;gap:.8rem;padding:.42rem .9rem;border-bottom:1px solid rgba(30,58,95,.4);font-size:.82rem; }
.kb-row:hover{ background:#0f2236; }

.sb-logo{ background:linear-gradient(135deg,#1d4ed8,#1e3a8a);border-radius:10px;padding:1rem 1.2rem;margin-bottom:1rem;text-align:center; }
.sb-title{ font-size:1.05rem;font-weight:800;color:#fff;letter-spacing:.02em; }
.sb-sub  { font-size:.7rem;color:rgba(255,255,255,.55);margin-top:3px; }

.pass-lbl{ color:#22c55e;font-weight:700;font-family:'JetBrains Mono',monospace;font-size:.8rem; }
.fail-lbl{ color:#ef4444;font-weight:700;font-family:'JetBrains Mono',monospace;font-size:.8rem; }
</style>
""", unsafe_allow_html=True)

# ── Session state ────────────────────────────────────────────
for k,v in {"page":"Dashboard","msg_step":1,"hyg_step":1,"hyg_data":{},
            "last_triggered":[],"last_scores":{},"last_cf":{},
            "last_explanation":{},"last_recs":{},"last_source":"","last_facts":{},
            "accumulated_facts":{}}.items():
    if k not in st.session_state: st.session_state[k]=v

# ── Constants ────────────────────────────────────────────────
SC = {"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}

def run_analysis(facts, source):
    t = run_inference(facts)
    s = build_score_report(t)
    # Accumulate facts across all analyses in the session
    st.session_state["accumulated_facts"].update(facts)
    st.session_state.update({
        "last_triggered":t,"last_scores":s,"last_cf":build_cf_report(t),
        "last_explanation":generate_explanation(t,s),"last_recs":get_recommendations(t),
        "last_source":source,"last_facts":facts,
    })
    st.session_state.page="Results"; st.rerun()

def sec(t): st.markdown(f'<div class="sec-lbl">{t}</div>',unsafe_allow_html=True)

def rbanner(label,score,source=""):
    icons={"CRITICAL":"[CRITICAL]","HIGH":"[HIGH]","MEDIUM":"[MEDIUM]","LOW":"[LOW]","SAFE":"[SAFE]"}
    s2=f" &nbsp;·&nbsp; <span style='font-weight:400;font-size:.85rem;color:#94a3b8'>{source}</span>" if source else ""
    st.markdown(f'<div class="result-banner banner-{label}"><span style="font-family:JetBrains Mono,monospace">{icons.get(label,label)}</span><div><div>{label} THREAT LEVEL</div><div style="font-weight:400;font-size:.83rem;margin-top:2px">Threat Score: {score:.0f}%{s2}</div></div></div>',unsafe_allow_html=True)

def srow(name,label,score):
    c=SC.get(label,"#7fa8c9")
    st.markdown(f'<div class="score-row"><span class="s-lbl">{name}</span><div style="flex:1;background:#1e3a5f;border-radius:5px;height:9px;overflow:hidden"><div style="width:{score:.0f}%;height:100%;background:{c};border-radius:5px;transition:width .5s"></div></div><span class="s-pill" style="background:{c}18;color:{c};border:1px solid {c}33">{label} &nbsp; {score:.0f}%</span></div>',unsafe_allow_html=True)

def rcard(rule,show_cond=False,facts=None):
    c=SC.get(rule["severity"],"#7fa8c9")
    st.markdown(f'<div class="rule-item {rule["severity"]}"><span class="r-id">{rule["id"]}</span><span class="r-desc">{rule["desc"]}</span><span class="r-sev" style="color:{c}">{rule["severity"]} {rule["confidence"]}%</span></div>',unsafe_allow_html=True)
    if show_cond and facts:
        html="".join(f'<span style="font-family:JetBrains Mono,monospace;font-size:.72rem;color:{"#22c55e" if facts.get(cond) else "#ef4444"};margin-right:.9rem">{"+" if facts.get(cond) else "-"} {cond}</span>' for cond in rule["conditions"])
        st.markdown(f'<div style="padding:.2rem 1rem .45rem 3.5rem">{html}</div>',unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="sb-logo"><div class="sb-title">CyberGuard Advisor</div><div class="sb-sub">Rule-Based Expert System</div></div>',unsafe_allow_html=True)
    PAGES=["Dashboard","Password Analyzer","URL Scanner","Message Detector",
           "Cyber Hygiene","Results","Recommendations","Explanation Engine",
           "Knowledge Base","Test Scenarios"]
    LABELS=["  Dashboard","  Password Analyzer","  URL Scanner","  Message Detector",
            "  Cyber Hygiene","  Threat Results","  Recommendations","  Explanation Engine",
            "  Knowledge Base","  Test Scenarios"]
    cur=PAGES.index(st.session_state.page) if st.session_state.page in PAGES else 0
    sel=st.radio("nav",LABELS,index=cur,label_visibility="collapsed")
    st.session_state.page=PAGES[LABELS.index(sel)]
    if st.session_state.last_scores:
        st.markdown("---")
        ov=st.session_state.last_scores.get("overall",{})
        lbl=ov.get("label","SAFE"); sc=ov.get("score",0); c=SC.get(lbl,"#7fa8c9")
        st.markdown(f'<div style="background:#0f2236;border:1px solid #1e3a5f;border-radius:8px;padding:.8rem 1rem"><div style="font-size:.67rem;color:#7fa8c9;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.3rem">Last Analysis</div><div style="color:{c};font-weight:700;font-size:.95rem">{lbl}</div><div style="color:#7fa8c9;font-size:.73rem;margin-top:2px">{sc:.0f}% &nbsp;·&nbsp; {len(st.session_state.last_triggered)} rules fired</div></div>',unsafe_allow_html=True)
    st.markdown('<div style="position:fixed;bottom:.8rem;left:1rem;color:#1e3a5f;font-size:.68rem">BS-CS AI Project · 2026</div>',unsafe_allow_html=True)

page=st.session_state.page

# ════════════════════════════════════════════════════════════
# DASHBOARD
# ════════════════════════════════════════════════════════════
if page=="Dashboard":
    if HERO_IMG:
        st.markdown(f'<div style="border-radius:14px;overflow:hidden;margin-bottom:.5rem;max-height:360px"><img src="data:image/jpeg;base64,{HERO_IMG}" style="width:100%;object-fit:cover;object-position:center 35%;max-height:360px;display:block"></div>',unsafe_allow_html=True)
    st.markdown('<div style="padding:1.2rem 0 .4rem 0"><h1 style="font-size:1.9rem;font-weight:800;color:#e2e8f0;margin:0">CyberGuard Advisor</h1><p style="color:#7fa8c9;font-size:.9rem;margin:.3rem 0 0 0">A rule-based cybersecurity expert system using forward chaining inference, MYCIN certainty factors, and explainable decision support.</p></div>',unsafe_allow_html=True)


    sec("SYSTEM OVERVIEW")
    c1,c2,c3,c4=st.columns(4)
    for col,lbl,val in [(c1,"Knowledge Base","80 Rules"),(c2,"Inference Engine","Forward Chaining"),(c3,"Reasoning Type","Explainable"),(c4,"Advanced Feature","Certainty Factor")]:
        with col: st.markdown(f'<div class="stack-card"><div class="lbl">{lbl}</div><div class="val">{val}</div></div>',unsafe_allow_html=True)

    sec("PROJECT STACK")
    p1,p2,p3,p4=st.columns(4)
    for col,lbl,val in [(p1,"Language","Python"),(p2,"Interface","Streamlit"),(p3,"IDE","PyCharm"),(p4,"Chaining","Forward + Backward")]:
        with col: st.markdown(f'<div class="stack-card"><div class="lbl">{lbl}</div><div class="val">{val}</div></div>',unsafe_allow_html=True)

    sec("DOMAIN COVERAGE")
    d1,d2,d3,d4,d5=st.columns(5)
    for col,name,rng,cnt in [(d1,"Password Security","R01-R18","18 rules"),(d2,"URL Safety","R19-R34","15 rules"),(d3,"Phishing Detection","R35-R50","15 rules"),(d4,"Scam Detection","R51-R66","14 rules"),(d5,"Cyber Hygiene","R67-R80","10 rules")]:
        with col:
            st.markdown(f'<div class="info-card" style="text-align:center"><div style="font-weight:700;font-size:.9rem;color:#e2e8f0;margin-bottom:.3rem">{name}</div><div style="font-family:JetBrains Mono,monospace;color:#3b82f6;font-size:.75rem">{rng}</div><div style="color:#7fa8c9;font-size:.76rem">{cnt}</div></div>',unsafe_allow_html=True)



# ════════════════════════════════════════════════════════════
# PASSWORD ANALYZER
# ════════════════════════════════════════════════════════════
elif page=="Password Analyzer":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Password Analyzer</h2><p style="color:#7fa8c9;font-size:.88rem">Evaluates password strength using 18 expert rules with certainty factor scoring.</p>',unsafe_allow_html=True)

    st.markdown('<div style="background:#0f2236;border:1px solid #1e3a5f;border-radius:10px;padding:1rem 1.4rem;margin-bottom:1rem"><div style="font-size:.82rem;color:#7fa8c9">The expert system evaluates 18 rules including length, complexity, keyboard patterns, and known compromised password lists.</div></div>',unsafe_allow_html=True)

    # Quick examples
    sec("QUICK TEST CASES")
    st.markdown('<div style="color:#7fa8c9;font-size:.78rem;margin-bottom:.5rem">Select an example to test the system.</div>',unsafe_allow_html=True)
    e1,e2,e3,e4=st.columns(4)
    for col,ex,lbl in [(e1,"123456","Very Weak"),(e2,"Hello2024","Moderate"),(e3,"qwerty","Keyboard Pattern"),(e4,"P@ssw0rd!XY99#","Strong")]:
        with col:
            if st.button(lbl,use_container_width=True,key=f"pe_{lbl}"):
                st.session_state["pwd_f"]=ex; st.rerun()

    # Password input form

    with st.form(key="pwd_form",clear_on_submit=False):
        c1f,c2f=st.columns([3,1])
        with c1f:
            username=st.text_input("Username or Email (optional)",placeholder="e.g. john@example.com",key="uname_f")
            pwd = st.text_input("Password", placeholder="Enter password to analyse", type="password", key="pwd_f")
        with c2f:
            st.markdown("<br>",unsafe_allow_html=True)
            show_pw=st.checkbox("Show as text",key="show_pw_f")
        if pwd:
            has_u=any(c.isupper() for c in pwd); has_d=any(c.isdigit() for c in pwd)
            has_s=any(c in "!@#$%^&*()_+-=[]{}|;:',.<>?/`~" for c in pwd)
            sv=min(len(pwd)/16,.9)*0.8+sum([has_u,has_d,has_s])*0.067; sv=min(sv,1.0)
            lt,lc=(("VERY STRONG","#22c55e") if sv>=.85 else ("STRONG","#22c55e") if sv>=.65 else ("MODERATE","#eab308") if sv>=.45 else ("WEAK","#f59e0b") if sv>=.25 else ("VERY WEAK","#ef4444"))
            st.markdown(f'<div style="font-family:JetBrains Mono,monospace;font-weight:700;font-size:.82rem;color:{lc};margin:.4rem 0">STRENGTH: {lt}</div>',unsafe_allow_html=True)
            st.progress(sv)
            m1,m2,m3,m4=st.columns(4)
            with m1: st.metric("Length",len(pwd))
            with m2: st.metric("Uppercase","Yes" if has_u else "No")
            with m3: st.metric("Digits","Yes" if has_d else "No")
            with m4: st.metric("Specials","Yes" if has_s else "No")
            if show_pw: st.code(pwd,language=None)
        submitted_pwd=st.form_submit_button("Run Password Analysis",use_container_width=True)
    if submitted_pwd:
        if not pwd: st.warning("Please enter a password.")
        else:
            st.session_state.last_scores={}
            run_analysis(extract_password_facts(pwd,username),"Password Analysis")

    # Show last result with direct link
    if st.session_state.last_scores and "Password" in st.session_state.get("last_source",""):
        ov=st.session_state.last_scores.get("overall",{})
        lbl=ov.get("label","SAFE"); sc2=ov.get("score",0)
        c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(lbl,"#7fa8c9")
        st.markdown(f'<div style="background:{c}15;border:1px solid {c}40;border-radius:8px;padding:.65rem 1.2rem;margin-top:.8rem;display:flex;align-items:center;gap:1.5rem"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace;font-size:.85rem">Last Analysis: {lbl} — {sc2:.0f}% threat score</span></div>',unsafe_allow_html=True)
        if st.button("View Threat Results",key="view_res_pwd",use_container_width=False):
            st.session_state.page="Results"; st.rerun()

# ════════════════════════════════════════════════════════════
# URL SCANNER
# ════════════════════════════════════════════════════════════
elif page=="URL Scanner":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">URL Scanner</h2><p style="color:#7fa8c9;font-size:.88rem">Detects phishing URLs, typosquatting, IP masking, and suspicious domain patterns using 15 rules.</p>',unsafe_allow_html=True)
    st.markdown('<div style="background:#0f2236;border:1px solid #1e3a5f;border-radius:10px;padding:1rem 1.4rem;margin-bottom:1rem"><div style="font-size:.82rem;color:#7fa8c9;margin-bottom:.7rem">Enter the full URL including protocol (http:// or https://). The system checks 15 rules for phishing indicators, suspicious domains, IP masking, and encoding tricks.</div></div>',unsafe_allow_html=True)
    url=st.text_input("URL",placeholder="https://www.example.com",label_visibility="collapsed")

    if st.session_state.last_scores and "URL" in st.session_state.last_source:
        ov=st.session_state.last_scores.get("overall",{})
        c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(ov.get("label","SAFE"),"#7fa8c9")
        st.markdown(f'<div style="background:{c}18;border:1px solid {c}44;border-radius:8px;padding:.7rem 1.2rem;margin:.5rem 0"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace">Last result: {ov.get("label","")} {ov.get("score",0):.0f}%</span></div>',unsafe_allow_html=True)
        if st.button("View Last Threat Results",use_container_width=False,key="view_results_url"):
            st.session_state.page="Results"; st.rerun()

    sec("QUICK TEST CASES")
    u1,u2,u3,u4=st.columns(4)
    for col,ex,lbl in [(u1,"https://www.google.com","Safe URL"),(u2,"http://paypa1-login.xyz/verify","Typosquatting"),(u3,"http://192.168.1.1/paypal/login","IP Address"),(u4,"http://trusted.com@evil.com/path","@ Symbol Trick")]:
        with col:
            if st.button(lbl,use_container_width=True,key=f"ue_{lbl}"):
                st.session_state["_uex"]=ex; st.rerun()
    if "_uex" in st.session_state:
        url=st.session_state["_uex"]; st.code(url,language=None)

    st.markdown("<br>",unsafe_allow_html=True)
    if st.button("Scan URL",use_container_width=True,key="url_go"):
        tgt=url or st.session_state.get("_uex","")
        if not tgt: st.warning("Please enter a URL.")
        else:
            st.session_state.last_scores={}
            run_analysis(extract_url_facts(tgt),f"URL: {tgt[:55]}{'...' if len(tgt)>55 else ''}")

    if st.session_state.last_scores and "URL" in st.session_state.get("last_source",""):
        ov=st.session_state.last_scores.get("overall",{})
        lbl=ov.get("label","SAFE"); sc2=ov.get("score",0)
        c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(lbl,"#7fa8c9")
        st.markdown(f'<div style="background:{c}15;border:1px solid {c}40;border-radius:8px;padding:.65rem 1.2rem;margin-top:.8rem"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace;font-size:.85rem">Last Analysis: {lbl} — {sc2:.0f}% threat score</span></div>',unsafe_allow_html=True)
        if st.button("View Threat Results",key="view_res_url"):
            st.session_state.page="Results"; st.rerun()

# ════════════════════════════════════════════════════════════
# MESSAGE DETECTOR  — 2-step
# ════════════════════════════════════════════════════════════
elif page=="Message Detector":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Message Detector</h2><p style="color:#7fa8c9;font-size:.88rem">Detects phishing, scam messages, and social engineering using 29 rules across 2 domains.</p>',unsafe_allow_html=True)
    step=st.session_state.get("msg_step",1)
    st.markdown(f'<div style="font-size:.8rem;color:#7fa8c9;margin:1rem 0 .4rem 0">Step {step} of 2: {"Message Type" if step==1 else "Message Content"}</div>',unsafe_allow_html=True)
    st.progress(step/2)

    SAMPLES={"OTP Phishing":"Dear Customer, Your account has been suspended. Please verify your OTP immediately to avoid account closure. Click: http://bit.ly/verify",
             "Prize Scam":"CONGRATULATIONS! You have won Rs.50,00,000 cash prize! Send Rs.500 processing fee via Easypaisa to claim today only!",
             "Nigerian Prince":"Dear Friend, I am Prince Emmanuel of Nigeria. I have $45 million to transfer. Please send advance fee of $500 via Western Union.",
             "Investment Fraud":"Earn 100% profit guaranteed! Double your money in 7 days with our crypto investment. Risk free, respond within 24 hours!",
             "Legitimate Email":"Hi John, the meeting is confirmed for Monday at 10 AM. Please review the attached agenda. Best regards, Sarah."}

    if step==1:
        st.markdown('<div class="step-card"><div class="step-title">Select Message Type</div><div class="step-sub">What type of message do you want to analyse?</div>',unsafe_allow_html=True)
        st.selectbox("Message Type",["Email","SMS / WhatsApp","Chat Message","Other"],label_visibility="collapsed",key="_mtype")
        st.markdown('</div>',unsafe_allow_html=True)
        sec("LOAD SAMPLE MESSAGE")
        cols=st.columns(5)
        for col,(lbl,txt) in zip(cols,SAMPLES.items()):
            with col:
                if st.button(lbl,use_container_width=True,key=f"ms_{lbl}"):
                    st.session_state["_msample"]=txt; st.session_state["msg_step"]=2; st.rerun()
        if st.button("Next: Enter Message",use_container_width=True):
            st.session_state["msg_step"]=2; st.rerun()
    else:
        st.markdown('<div class="step-card"><div class="step-title">Paste Message Content</div><div class="step-sub">Enter the complete message text to be analysed by the expert system.</div>',unsafe_allow_html=True)
        msg=st.text_area("Message",value=st.session_state.get("_msample",""),height=140,placeholder="Paste full message text here...",label_visibility="collapsed")
        st.markdown('</div>',unsafe_allow_html=True)
        b1,b2=st.columns([1,4])
        with b1:
            if st.button("Back",key="mb"): st.session_state["msg_step"]=1; st.session_state["_msample"]=""; st.rerun()
        with b2:
            if st.button("Analyse Message",use_container_width=True,key="mg"):
                if not msg.strip(): st.warning("Please paste a message.")
                else:
                    st.session_state.last_scores={}
                    run_analysis({**extract_message_facts(msg),**extract_scam_facts(msg)},"Message Analysis")

        if st.session_state.last_scores and "Message" in st.session_state.get("last_source",""):
            ov=st.session_state.last_scores.get("overall",{})
            lbl=ov.get("label","SAFE"); sc2=ov.get("score",0)
            c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(lbl,"#7fa8c9")
            st.markdown(f'<div style="background:{c}15;border:1px solid {c}40;border-radius:8px;padding:.65rem 1.2rem;margin-top:.8rem"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace;font-size:.85rem">Last Analysis: {lbl} — {sc2:.0f}% threat score</span></div>',unsafe_allow_html=True)
            if st.button("View Threat Results",key="view_res_msg"):
                st.session_state.page="Results"; st.rerun()

# ════════════════════════════════════════════════════════════
# CYBER HYGIENE  — 3-step, statement-style Yes/No dropdowns
# ════════════════════════════════════════════════════════════
elif page=="Cyber Hygiene":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Cyber Hygiene Assessment</h2><p style="color:#7fa8c9;font-size:.88rem">Evaluates your cybersecurity habits using 10 expert rules. Answer each statement honestly.</p>',unsafe_allow_html=True)
    hs=st.session_state.get("hyg_step",1)
    steps_h=["Password & Account Security","Device & Network Security","Online Behaviour"]
    st.markdown(f'<div style="font-size:.8rem;color:#7fa8c9;margin:1rem 0 .4rem 0">Step {hs} of {len(steps_h)}: {steps_h[hs-1]}</div>',unsafe_allow_html=True)
    st.progress(hs/len(steps_h))
    d=st.session_state.get("hyg_data",{})

    YN  = ["No","Yes"]
    FRQ = ["Never","Rarely","Sometimes","Often","Always"]

    def yn_box(label, key, default="No"):
        stored = d.get(key, default)
        idx = YN.index(stored) if stored in YN else YN.index(default)
        return st.selectbox(label, YN, index=idx, key=f"hq_{key}")

    def frq_box(label, key, default="Never"):
        stored = d.get(key, default)
        val = stored if stored in FRQ else default
        return st.select_slider(label, options=FRQ, value=val, key=f"hq_{key}")

    if hs==1:
        st.markdown('<div class="step-card"><div class="step-title">Password & Account Security</div><div class="step-sub">Select the option that best describes your current practice.</div>',unsafe_allow_html=True)
        c1,c2 = st.columns(2)
        with c1:
            r1 = frq_box("I use the same password for different accounts","pw_reuse","Never")
            r2 = yn_box("I do not use two-factor authentication (2FA) on my accounts","no_2fa","No")
        with c2:
            r3 = frq_box("I share my passwords with friends, family, or colleagues","pw_share","Never")
            r4 = yn_box("My passwords are short (less than 8 characters)","short_pwd","No")
        st.markdown('</div>',unsafe_allow_html=True)

        d["pw_reuse"]=r1; d["no_2fa_val"]=r2; d["pw_share"]=r3; d["short_pwd_val"]=r4
        d["password_reuse"]   = r1 in ["Often","Always"]
        d["no_2fa"]           = r2 == "Yes"
        d["shares_passwords"] = r3 in ["Often","Always"]
        st.session_state["hyg_data"]=d
        if st.button("Next: Device & Network Security",use_container_width=True,key="hn1"):
            st.session_state["hyg_step"]=2; st.rerun()

    elif hs==2:
        st.markdown('<div class="step-card"><div class="step-title">Device & Network Security</div><div class="step-sub">Select the option that best describes your current practice.</div>',unsafe_allow_html=True)
        c1,c2 = st.columns(2)
        with c1:
            r5 = yn_box("I do not have antivirus or security software installed","no_av","No")
            r6 = yn_box("I rarely or never update my OS or applications","no_upd","No")
        with c2:
            r7 = frq_box("I connect to public Wi-Fi without using a VPN","pub_wifi","Never")
            r8 = yn_box("I use the same Wi-Fi password for years without changing","old_wifi","No")
        st.markdown('</div>',unsafe_allow_html=True)

        d["no_av_val"]=r5; d["no_upd_val"]=r6; d["pub_wifi"]=r7; d["old_wifi_val"]=r8
        d["no_antivirus"] = r5 == "Yes"
        d["no_updates"]   = r6 == "Yes"
        d["public_wifi"]  = r7 in ["Often","Always"]
        st.session_state["hyg_data"]=d
        b1,b2=st.columns([1,4])
        with b1:
            if st.button("Back",key="hb1"): st.session_state["hyg_step"]=1; st.rerun()
        with b2:
            if st.button("Next: Online Behaviour",use_container_width=True,key="hn2"):
                st.session_state["hyg_step"]=3; st.rerun()

    else:
        st.markdown('<div class="step-card"><div class="step-title">Online Behaviour</div><div class="step-sub">Select the option that best describes your current practice.</div>',unsafe_allow_html=True)
        c1,c2 = st.columns(2)
        with c1:
            r9  = yn_box("I open email attachments from unknown or unverified senders","open_att","No")
            r10 = yn_box("I click on links in emails without checking the sender","click_links","No")
        with c2:
            r11 = frq_box("I download software or apps from unofficial sources","dl_unoff","Never")
            r12 = yn_box("I ignore browser security warnings when visiting websites","ignore_warn","No")
        st.markdown('</div>',unsafe_allow_html=True)

        d["open_att_val"]=r9; d["click_links_val"]=r10; d["dl_unoff"]=r11; d["ignore_warn_val"]=r12
        d["opens_attachments"] = r9 == "Yes"
        st.session_state["hyg_data"]=d

        risks = sum([
            d.get("password_reuse",False), d.get("shares_passwords",False),
            d.get("no_2fa",False),         d.get("no_updates",False),
            d.get("no_antivirus",False),   d.get("public_wifi",False),
            d.get("opens_attachments",False),
        ])
        if risks > 0:
            st.markdown(f'<div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);border-radius:8px;padding:.7rem 1rem;color:#f59e0b;font-size:.84rem;margin:.5rem 0">{risks} risk factor(s) identified — run assessment to see detailed analysis</div>',unsafe_allow_html=True)

        b1,b2=st.columns([1,4])
        with b1:
            if st.button("Back",key="hb2"): st.session_state["hyg_step"]=2; st.rerun()
        with b2:
            if st.button("Run Assessment",use_container_width=True,key="hgo"):
                st.session_state.last_scores={}
                run_analysis(extract_hygiene_facts(st.session_state["hyg_data"]),"Cyber Hygiene Assessment")
                st.session_state["hyg_step"]=1

        if st.session_state.last_scores and "Hygiene" in st.session_state.get("last_source",""):
            ov=st.session_state.last_scores.get("overall",{})
            lbl=ov.get("label","SAFE"); sc2=ov.get("score",0)
            c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(lbl,"#7fa8c9")
            st.markdown(f'<div style="background:{c}15;border:1px solid {c}40;border-radius:8px;padding:.65rem 1.2rem;margin-top:.8rem"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace;font-size:.85rem">Last Analysis: {lbl} — {sc2:.0f}% threat score</span></div>',unsafe_allow_html=True)
            if st.button("View Threat Results",key="view_res_hyg"):
                st.session_state.page="Results"; st.rerun()

# ════════════════════════════════════════════════════════════
# RESULTS
# ════════════════════════════════════════════════════════════
elif page=="Results":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Threat Results</h2>',unsafe_allow_html=True)
    if not st.session_state.last_scores:
        st.info("No analysis run yet. Use any module from the sidebar.")
    else:
        sc=st.session_state.last_scores; cf=st.session_state.last_cf
        tr=st.session_state.last_triggered; src=st.session_state.last_source
        ov=sc.get("overall",{"score":0,"label":"SAFE"}); cfo=cf.get("overall",{"cf_score":0,"label":"SAFE"})
        rbanner(ov["label"],ov["score"],src)
        m1,m2,m3,m4,m5=st.columns(5)
        with m1: st.metric("Threat Level",ov["label"])
        with m2: st.metric("Threat Score",f"{ov['score']:.0f}%")
        with m3: st.metric("CF Score",f"{cfo['cf_score']:.0f}%")
        with m4: st.metric("Rules Fired",len(tr))
        with m5: st.metric("Critical Rules",sum(1 for r in tr if r["severity"]=="CRITICAL"))
        page_map={"Password Analysis":"Password Analyzer","URL":"URL Scanner","Message":"Message Detector","Cyber Hygiene":"Cyber Hygiene"}
        back_page=next((v for k,v in page_map.items() if k in src),"Password Analyzer")
        ba,bb=st.columns([1,5])
        with ba:
            if st.button("Run New Analysis",key="new_ana",use_container_width=True):
                st.session_state.last_scores={}; st.session_state.last_triggered=[]
                st.session_state.last_explanation={}; st.session_state.last_recs={}
                st.session_state.page=back_page; st.rerun()

        t1,t2=st.tabs(["Score Breakdown","Triggered Rules"])
        with t1:
            sec("CATEGORY THREAT SCORES")
            cats=[("password","Password"),("url","URL"),("phishing","Phishing"),("scam","Scam"),("hygiene","Hygiene")]
            shown=False
            for k,n in cats:
                s=sc.get(k,{"score":0,"label":"SAFE"})
                if s["score"]>0: srow(n,s["label"],s["score"]); shown=True
            if not shown: st.markdown('<div style="color:#22c55e;padding:.8rem;font-size:.88rem">All categories: No threats detected</div>',unsafe_allow_html=True)

            sec("CERTAINTY FACTOR SCORES — MYCIN CF Algebra")
            st.markdown('<div style="color:#7fa8c9;font-size:.78rem;margin-bottom:.5rem">CF scores are combined using MYCIN algebra: CF(A,B) = CF(A) + CF(B)×(1-CF(A)). This prevents dilution of CRITICAL findings by lower-severity rules.</div>',unsafe_allow_html=True)
            for k,n in cats:
                s=cf.get(k,{"cf_score":0,"label":"SAFE"})
                if s["cf_score"]>0: srow(f"{n} (CF)",s["label"],s["cf_score"])

            sec("CONFLICT RESOLUTION")
            st.markdown('<div style="color:#7fa8c9;font-size:.78rem;margin-bottom:.5rem">When multiple rules fire in the same domain, the highest-severity rule takes precedence: CRITICAL > HIGH > MEDIUM > LOW.</div>',unsafe_allow_html=True)
            res=resolve_conflicts(tr)
            if res:
                for cat,rule in res.items():
                    c=SC.get(rule["severity"],"#7fa8c9")
                    st.markdown(f'<div class="info-card" style="border-left:3px solid {c}"><span style="color:#7fa8c9;font-size:.77rem">{cat.upper()}: </span><span style="color:#60a5fa;font-family:JetBrains Mono,monospace;font-weight:600">{rule["id"]}</span><span style="color:#94a3b8;font-size:.83rem"> — {rule["desc"]}</span><span style="float:right;color:{c};font-weight:700;font-size:.77rem;font-family:JetBrains Mono,monospace">{rule["severity"]}</span></div>',unsafe_allow_html=True)
        with t2:
            sec(f"ALL TRIGGERED RULES  ({len(tr)} fired)")
            if tr:
                for rule in tr: rcard(rule)
            else:
                st.markdown('<div style="color:#22c55e;padding:.8rem;font-size:.88rem">No rules triggered — no threats found.</div>',unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════
# RECOMMENDATIONS
# ════════════════════════════════════════════════════════════
elif page=="Recommendations":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Recommendations</h2><p style="color:#7fa8c9;font-size:.88rem">Actionable security guidance generated from triggered rules.</p>',unsafe_allow_html=True)
    if not st.session_state.last_recs:
        st.info("Run an analysis first.")
    else:
        r=st.session_state.last_recs
        if r.get("specific"):
            sec(f"SPECIFIC RECOMMENDATIONS  ({len(r['specific'])} items)")
            for x in r["specific"]: st.markdown(f'<div class="rec-s">{x.strip()}</div>',unsafe_allow_html=True)
        sec("GENERAL SECURITY GUIDELINES")
        for x in r.get("general",[]): st.markdown(f'<div class="rec-g">{x.strip()}</div>',unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════
# EXPLANATION ENGINE
# ════════════════════════════════════════════════════════════
elif page=="Explanation Engine":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Explanation Engine</h2><p style="color:#7fa8c9;font-size:.88rem">Full reasoning trace — which rules fired, why conditions were true, and backward chaining verification.</p>',unsafe_allow_html=True)
    if not st.session_state.last_explanation:
        st.info("Run an analysis first.")
    else:
        exp=st.session_state.last_explanation; sc=st.session_state.last_scores; facts=st.session_state.last_facts
        rbanner(exp.get("overall_label","SAFE"),exp.get("overall_score",0))
        t1,t2,t3=st.tabs(["Forward Chaining Trace","Backward Chaining","Full Report"])

        with t1:
            sec("FORWARD CHAINING — HOW INFERENCE WORKS")
            st.markdown('<div style="color:#7fa8c9;font-size:.82rem;margin-bottom:.8rem">The inference engine iterates all 80 rules. Each rule fires if and only if ALL its conditions are TRUE in the current fact base (AND logic). Fired rules add conclusions to working memory. This continues until no more rules fire (fixed-point).</div>',unsafe_allow_html=True)
            for cat,info in exp.get("by_category",{}).items():
                with st.expander(f"{info['label']}  —  {info['level']}  ({info['score']:.0f}%)"):
                    st.markdown(f'<div style="color:#94a3b8;font-size:.84rem;line-height:1.7;margin-bottom:.7rem">{info["narrative"]}</div>',unsafe_allow_html=True)
                    sec("FIRED RULES — CONDITION TRUTH VALUES")
                    for rule in info.get("rules",[]):
                        rcard(rule,show_cond=True,facts=facts)

        with t2:
            sec("BACKWARD CHAINING — GOAL-DRIVEN PROOF")
            st.markdown('<div style="color:#7fa8c9;font-size:.82rem;margin-bottom:.8rem">Backward chaining starts from a goal hypothesis and works backwards to find supporting rules and evidence. This is the goal-driven complement to forward chaining.</div>',unsafe_allow_html=True)
            # Check if multiple domains have been analysed
            acc_facts = st.session_state.get("accumulated_facts", {})
            if len(acc_facts) > len(facts):
                st.markdown('<div style="background:#1e3a5f22;border:1px solid #1e3a5f;border-radius:8px;padding:.65rem 1rem;margin-bottom:.8rem;font-size:.8rem;color:#7fa8c9">Backward chaining uses <b style="color:#22c55e">all analyses from this session</b> (Password, URL, Message, and Hygiene facts are combined). You can verify goals across any domain you have analysed.</div>',unsafe_allow_html=True)
            else:
                st.markdown('<div style="background:#1e3a5f22;border:1px solid #1e3a5f;border-radius:8px;padding:.65rem 1rem;margin-bottom:.8rem;font-size:.8rem;color:#7fa8c9">Backward chaining uses the fact base from all analyses run in this session. For richer results, run multiple analysers (Password, URL, Message, Hygiene) before verifying goals here.</div>',unsafe_allow_html=True)
            # Auto-select domain based on last analysis
            src=st.session_state.get("last_source","")
            domain_hint=("password" if "Password" in src else "url" if "URL" in src else "phishing" if "Message" in src else "hygiene" if "Hygiene" in src else "password")
            dom_options=["password","url","phishing","scam","hygiene"]
            dom=st.selectbox("Select domain to verify",dom_options,index=dom_options.index(domain_hint))
            if st.button("Run Backward Chaining",key="bcb"):
                # Use accumulated facts so all prior analyses are included
                bc_facts = st.session_state.get("accumulated_facts", facts)
                bc=run_backward_chaining(bc_facts,dom)
                proved=bc.get(dom,[])
                if proved:
                    for pg in proved:
                        c=SC.get("HIGH","#f59e0b")
                        st.markdown(f'<div class="info-card" style="border-left:3px solid {c}"><b style="color:#e2e8f0">Goal proved:</b> <code style="color:#60a5fa">{pg["goal"]}</code> &nbsp; CF: {pg["confidence"]}%</div>',unsafe_allow_html=True)
                        with st.expander("Step-by-step reasoning trace"):
                            for line in pg["trace"]:
                                col="#22c55e" if "PROVED" in line and "NOT" not in line else "#ef4444" if "NOT proved" in line else "#94a3b8"
                                st.markdown(f'<div style="font-family:JetBrains Mono,monospace;font-size:.75rem;color:{col};line-height:1.6">{line}</div>',unsafe_allow_html=True)
                else:
                    st.markdown('<div style="color:#7fa8c9;padding:.8rem;font-size:.85rem">No goals proved for this domain with current facts.</div>',unsafe_allow_html=True)

        with t3:
            sec("COMPLETE ANALYSIS REPORT")
            rpt=format_full_report(exp,sc)
            st.markdown(f'<div class="mono-rpt">{rpt}</div>',unsafe_allow_html=True)
            st.download_button("Download Report (.txt)",data=rpt,file_name="cyberguard_report.txt",mime="text/plain")

# ════════════════════════════════════════════════════════════
# KNOWLEDGE BASE
# ════════════════════════════════════════════════════════════
elif page=="Knowledge Base":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Knowledge Base</h2><p style="color:#7fa8c9;font-size:.88rem">All 72 production rules with conditions, certainty factors, and knowledge acquisition sources.</p>',unsafe_allow_html=True)

    sec("KNOWLEDGE ACQUISITION METHODOLOGY")
    st.markdown("""<div class="info-card">
      <div style="font-size:.84rem;color:#94a3b8;line-height:1.9">
        Rules were derived from five authoritative expert sources:<br>
        <b style="color:#e2e8f0">1. OWASP Top 10 (2023)</b> — Password complexity, URL phishing patterns, injection attack signatures<br>
        <b style="color:#e2e8f0">2. NIST SP 800-63B</b> — Password entropy standards, common password blacklists, minimum length requirements<br>
        <b style="color:#e2e8f0">3. Anti-Phishing Working Group (APWG)</b> — Real phishing URL and message patterns from quarterly eCrime reports<br>
        <b style="color:#e2e8f0">4. FTC Consumer Sentinel Network</b> — Scam detection patterns from fraud reports database<br>
        <b style="color:#e2e8f0">5. CIS Controls v8 / SANS Awareness</b> — Cyber hygiene rules based on critical security controls baseline<br>
        Certainty factors (0-100%) represent empirical precision rates from published cybersecurity research.
      </div></div>""",unsafe_allow_html=True)

    sec("HOW RULES WERE DERIVED")
    st.markdown("""<div class="info-card">
      <div style="font-size:.84rem;color:#94a3b8;line-height:1.9">
        <b style="color:#e2e8f0">Step 1 — Domain Selection:</b> Five cybersecurity domains were identified based on the MITRE ATT&CK framework attack surface.<br>
        <b style="color:#e2e8f0">Step 2 — Pattern Extraction:</b> Known attack patterns, IOCs (Indicators of Compromise), and security checklists were collected from OWASP, NIST, APWG.<br>
        <b style="color:#e2e8f0">Step 3 — Rule Encoding:</b> Each pattern was encoded as IF (conditions) THEN (conclusion) with severity reflecting real-world impact.<br>
        <b style="color:#e2e8f0">Step 4 — CF Assignment:</b> Certainty factors were assigned based on precision rates in threat detection literature.<br>
        <b style="color:#e2e8f0">Step 5 — Conflict Resolution:</b> Conflicting rules in the same domain are resolved by severity priority (CRITICAL > HIGH > MEDIUM > LOW).
      </div></div>""",unsafe_allow_html=True)

    sec("RULE BROWSER")
    fc1,fc2=st.columns(2)
    with fc1: cf=st.selectbox("Filter Domain",["All","password","url","phishing","scam","hygiene"])
    with fc2: sf=st.selectbox("Filter Severity",["All","CRITICAL","HIGH","MEDIUM","LOW"])
    filtered=[r for r in RULES if (cf=="All" or r["category"]==cf) and (sf=="All" or r["severity"]==sf)]
    st.markdown(f'<div style="color:#7fa8c9;font-size:.76rem;margin:.4rem 0">{len(filtered)} rules shown</div>',unsafe_allow_html=True)
    st.markdown('<div class="kb-row" style="border-bottom:2px solid #1e3a5f;font-weight:700;color:#3b82f6;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em"><span style="min-width:42px">ID</span><span style="min-width:85px">Domain</span><span style="flex:1">Description</span><span style="min-width:80px">Severity</span><span style="min-width:42px">CF%</span></div>',unsafe_allow_html=True)
    for rule in filtered:
        c=SC.get(rule["severity"],"#7fa8c9")
        st.markdown(f'<div class="kb-row"><span style="min-width:42px;color:#60a5fa;font-family:JetBrains Mono,monospace;font-weight:600;font-size:.8rem">{rule["id"]}</span><span style="min-width:85px;color:#7fa8c9;font-size:.76rem">{rule["category"]}</span><span style="flex:1;color:#94a3b8;font-size:.82rem">{rule["desc"]}</span><span style="min-width:80px;color:{c};font-weight:700;font-size:.75rem;font-family:JetBrains Mono,monospace">{rule["severity"]}</span><span style="min-width:42px;color:#7fa8c9;font-family:JetBrains Mono,monospace;font-size:.75rem">{rule["confidence"]}</span></div>',unsafe_allow_html=True)
        if st.session_state.get(f"show_rat_{rule['id']}"):
            if rule.get("rationale"):
                st.markdown(f'<div style="padding:.3rem 1rem .4rem 3.5rem;font-size:.76rem;color:#7fa8c9;font-style:italic">{rule["rationale"]}</div>',unsafe_allow_html=True)

    with st.expander("View Rule Structure Example"):
        st.code("""{
  "id":         "R01",
  "desc":       "Very short password with no special characters",
  "category":   "password",
  "conditions": ["pwd_length_very_short", "no_special_char"],
  "conclusion": "password_risk_critical",
  "severity":   "CRITICAL",
  "confidence": 95,
  "rationale":  "NIST 800-63B: passwords < 6 chars have near-zero entropy"
}
# Inference: IF pwd_length_very_short=TRUE AND no_special_char=TRUE
#            THEN conclusion=password_risk_critical  (CF=95%)""",language="python")

# ════════════════════════════════════════════════════════════
# TEST SCENARIOS
# ════════════════════════════════════════════════════════════
elif page=="Test Scenarios":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Test Scenarios</h2><p style="color:#7fa8c9;font-size:.88rem">14 predefined test cases across all 5 domains. Validates system accuracy and rule correctness.</p>',unsafe_allow_html=True)
    if st.button("Run All 14 Test Scenarios",use_container_width=True):
        results=[]; prog=st.progress(0); status=st.empty()
        for i,tc in enumerate(TEST_SCENARIOS):
            status.markdown(f'<div style="color:#7fa8c9;font-size:.8rem">Running {tc["id"]}: {tc["name"]}...</div>',unsafe_allow_html=True)
            prog.progress((i+1)/len(TEST_SCENARIOS))
            if tc["input_type"]=="password": f=extract_password_facts(tc["input"]["password"],tc["input"].get("username",""))
            elif tc["input_type"]=="url": f=extract_url_facts(tc["input"]["url"])
            elif tc["input_type"]=="message": f={**extract_message_facts(tc["input"]["message"]),**extract_scam_facts(tc["input"]["message"])}
            else: f=extract_hygiene_facts(tc["input"])
            tr=run_inference(f); s=build_score_report(tr)
            ov=s.get("overall",{"label":"SAFE","score":0}); fired=[r["id"] for r in tr]
            ef=any(e in fired for e in tc["expected_rules"])
            so=(ov["label"]==tc["expected_severity"] or
                (tc["expected_severity"] in ["LOW","SAFE"] and ov["label"] in ["LOW","SAFE"]) or
                (tc["expected_severity"]=="CRITICAL" and ov["label"] in ["CRITICAL","HIGH"]))
            ok=ef and so
            results.append({**tc,"passed":ok,"actual_label":ov["label"],"actual_score":ov["score"],"fired_ids":fired})
            time.sleep(0.03)
        status.empty(); prog.empty()
        pc=sum(1 for r in results if r["passed"]); acc=pc/len(results)*100
        rbanner("LOW" if pc==len(results) else "MEDIUM",acc,f"{pc}/{len(results)} test cases passed")
        m1,m2,m3=st.columns(3)
        with m1: st.metric("Tests Passed",f"{pc}/{len(results)}")
        with m2: st.metric("Accuracy",f"{acc:.1f}%")
        with m3: st.metric("Failed",len(results)-pc)
        sec("DETAILED RESULTS")
        for r in results:
            ec=SC.get(r["actual_label"],"#7fa8c9")
            with st.expander(f"{r['id']} — {r['name']}"):
                st.markdown(f'<div style="display:flex;gap:2rem;align-items:center;margin-bottom:.7rem"><span class="{"pass-lbl" if r["passed"] else "fail-lbl"}">{"PASS" if r["passed"] else "FAIL"}</span><span style="font-size:.82rem;color:#7fa8c9">Expected: <b style="color:#e2e8f0">{r["expected_severity"]}</b></span><span style="font-size:.82rem;color:#7fa8c9">Actual: <b style="color:{ec}">{r["actual_label"]} ({r["actual_score"]:.0f}%)</b></span></div>',unsafe_allow_html=True)
                st.markdown(f'<div style="font-size:.83rem;color:#94a3b8;margin-bottom:.3rem"><b style="color:#e2e8f0">Description:</b> {r["description"]}</div>',unsafe_allow_html=True)
                st.markdown(f'<div style="font-size:.83rem;color:#94a3b8;margin-bottom:.5rem"><b style="color:#e2e8f0">Rationale:</b> {r["rationale"]}</div>',unsafe_allow_html=True)
                st.markdown(f'<div style="font-family:JetBrains Mono,monospace;font-size:.74rem;color:#7fa8c9">Expected rules: <span style="color:#60a5fa">{", ".join(r["expected_rules"])}</span><br>Rules fired: <span style="color:#94a3b8">{", ".join(r["fired_ids"][:10])}</span></div>',unsafe_allow_html=True)
    else:
        sec("TEST CASES OVERVIEW")
        st.markdown('<div class="kb-row" style="border-bottom:2px solid #1e3a5f;font-weight:700;color:#3b82f6;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em"><span style="min-width:42px">ID</span><span style="min-width:90px">Domain</span><span style="flex:1">Scenario Name</span><span style="min-width:90px">Expected</span></div>',unsafe_allow_html=True)
        for tc in TEST_SCENARIOS:
            c=SC.get(tc["expected_severity"],"#7fa8c9")
            st.markdown(f'<div class="kb-row"><span style="min-width:42px;color:#60a5fa;font-family:JetBrains Mono,monospace;font-weight:600;font-size:.8rem">{tc["id"]}</span><span style="min-width:90px;color:#7fa8c9;font-size:.77rem">{tc["domain"]}</span><span style="flex:1;color:#94a3b8;font-size:.83rem">{tc["name"]}</span><span style="min-width:90px;color:{c};font-weight:700;font-size:.75rem;font-family:JetBrains Mono,monospace">{tc["expected_severity"]}</span></div>',unsafe_allow_html=True)
