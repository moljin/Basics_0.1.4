"use strict"

/*jshint esversion: 8 */

articleDeleteInit();

function articleDeleteInit() {
    const deleteBtn = document.getElementById("deleteBtn");
    if (!deleteBtn) return;

    deleteBtn.addEventListener("click", async (e) => {
        e.preventDefault();
        // 확인/취소 확인창
        const confirmed = window.confirm("정말 이 게시글을 삭제하시겠습니까?\n삭제 후에는 복구할 수 없습니다.");
        if (!confirmed) return;

        // 중복 클릭 방지 표시(필요 시 클래스/스타일은 프로젝트에 맞게 조정)
        deleteBtn.setAttribute("aria-busy", "true");

        const articleIdValue = document.getElementById("article_id")?.value;
        if (!articleIdValue) {
            alert("게시글 ID를 찾을 수 없습니다.");
            deleteBtn.removeAttribute("aria-busy");
            return;
        }

        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute("content");
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000);

        try {
            const response = await fetch("/apis/articles/"+articleIdValue, {
                method: "DELETE",
                headers: {"X-CSRF-Token": csrfToken},
                signal: controller.signal,
            });

            const result = await response.json().catch(() => ({}));

            if (!response.ok) {
                console.error("Withdraw failed", response.status);
                alert("삭제에 실패했습니다. 잠시 후 다시 시도해 주세요.");
                return;
            }

            alert(result?.detail || "게시글 삭제가 완료되었습니다.");
            window.location.href = `/articles`;
        } catch (err) {
            if (err.name === "AbortError") {
                alert("요청이 시간 초과되었습니다. 네트워크 상태를 확인한 뒤 다시 시도해 주세요.");
            } else {
                console.error("Delete error", err);
                alert("삭제 처리 중 오류가 발생했습니다.");
            }
        } finally {
            deleteBtn.removeAttribute("aria-busy");
            clearTimeout(timeoutId);
        }

    });
}