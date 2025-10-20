"use strict"

/*jshint esversion: 8 */

logoutInit();
function logoutInit() {
    const logoutBtn = document.getElementById("logoutBtn");
    if (!logoutBtn) return;

    logoutBtn.addEventListener("click", async (e) => {
        e.preventDefault();
        // 중복 클릭 방지 표시(필요 시 클래스/스타일은 프로젝트에 맞게 조정)
        logoutBtn.setAttribute("aria-busy", "true");

        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000);

        try {
            const response = await fetch("/accounts/logout", {
                method: "POST",
                headers: {"X-CSRF-Token": csrfToken},
                signal: controller.signal,
            });

            if (!response.ok) {
                console.error("Logout failed", response.status);
                alert("로그아웃에 실패했습니다. 잠시 후 다시 시도해 주세요.");
                return;
            }

            window.location.href = `/`;
        } catch (err) {
            if (err.name === "AbortError") {
                alert("요청이 시간 초과되었습니다. 네트워크 상태를 확인한 뒤 다시 시도해 주세요.");
            } else {
                console.error("Logout error", err);
                alert("로그아웃 처리 중 오류가 발생했습니다.");
            }
        } finally {
            logoutBtn.removeAttribute("aria-busy");
            clearTimeout(timeoutId);
        }

    });
}
