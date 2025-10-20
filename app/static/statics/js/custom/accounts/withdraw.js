"use strict"

/*jshint esversion: 8 */

accountWithDrawInit();
function accountWithDrawInit() {
    const withDrawBtn = document.getElementById("withDrawBtn");
    if (!withDrawBtn) return;

    withDrawBtn.addEventListener("click", async (e) => {
        e.preventDefault();
        // 확인/취소 확인창
        const confirmed = window.confirm("정말로 회원을 탈퇴하시겠습니까?\n관련 모든 데이터가 삭제되고, 작업 후 되돌릴 수 없습니다.");
        if (!confirmed) {
            // 사용자가 취소를 눌렀습니다.
            return;
        }

        // 중복 클릭 방지
        withDrawBtn.classList.add("is-loading");
        withDrawBtn.setAttribute("aria-busy", "true");
        withDrawBtn.style.pointerEvents = "none";

        const userIdValue = document.getElementById("user_id")?.value;


        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000);
        try {
            const response = await fetch("/apis/accounts/delete/"+userIdValue, {
                method: "DELETE",
                headers: {"X-CSRF-Token": csrfToken},
                signal: controller.signal
            });

            const result = await response.json().catch(() => ({}));

            if (!response.ok) {
                const msg = result?.detail || `회원 탈퇴 요청이 실패했습니다. (code: ${response.status})`;
                alert(msg);
                return;
            }

            alert(result?.detail || "회원 탈퇴가 완료되었습니다.");
            window.location.href = `/`;
        } catch (err) {
            if (err.name === "AbortError") {
                alert("요청 시간이 초과되었습니다. 잠시 후 다시 시도해 주세요.");
            } else {
                console.error("Withdraw error", err);
                alert("회원 탈퇴 처리 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
            }
        } finally {
            withDrawBtn.classList.remove("is-loading");
            withDrawBtn.removeAttribute("aria-busy");
            withDrawBtn.style.pointerEvents = "";
            clearTimeout(timeoutId);
        }



    });
}