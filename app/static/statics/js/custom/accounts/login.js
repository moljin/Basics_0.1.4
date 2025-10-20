"use strict"

// /*jshint esversion: 8 */
/*jshint esversion: 11 */

loginInit();

function loginInit() {
    const accountForm = document.getElementById("accountForm");
    if (!accountForm) return;

    accountForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const errorEl = document.getElementById("errorTag");

        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000);

        const formData = new FormData(e.target);
        const jsonData = Object.fromEntries(formData.entries());


        const response = await fetch("/apis/auth/login", {
            method: "POST",
            headers: {"Content-Type": "application/json", "X-CSRF-Token": csrfToken},
            body: JSON.stringify(jsonData),
            signal: controller.signal
        });


        try {
            const result = await response.json();

            if (response.ok) {
                const hasDetail = Object.prototype.hasOwnProperty.call(result, "detail");
                const detail = result.detail;
                // 성공(메시지 없음) 처리
                if (!hasDetail || detail === null) { // == null 은 null 또는 undefined 모두 true
                    window.location.href = "/";
                } else {
                    // 백엔드에서 custom_http_exception_handler 411 JSONResponse
                    if (detail === "인증 실패") {
                        errorEl.innerText = `❌ 오류: 회원이 존재하지 않습니다.`;
                    }
                    if (detail === "비밀번호 불일치") {
                        errorEl.innerText = `❌ 오류: 비밀번호가 일치하지 않습니다.`;
                    }
                }
            } else {
                errorEl.innerText = `❌ 오류: ${result.detail}`;
            }
        } catch (err) {
            if (err.name === "AbortError") {
                alert("요청 시간이 초과되었습니다. 잠시 후 다시 시도해 주세요.");
            } else {
                console.error("Login error", err);
                alert("로그인 과정 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.");
            }
        } finally {
            clearTimeout(timeoutId);
        }


    });
}