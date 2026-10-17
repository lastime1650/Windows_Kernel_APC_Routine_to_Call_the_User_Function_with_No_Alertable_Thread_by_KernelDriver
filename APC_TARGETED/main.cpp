#include <Windows.h>
#include <stdio.h>

int main()
{
    const DWORD pid = GetCurrentProcessId();
    const DWORD tid = GetCurrentThreadId();

    // User APC Callback
    // x64: NTAPI와 기본 호출 규약 동일
    auto UserApcCallback = +[]() -> VOID
        {

            printf(
                "\n[APC EXECUTED] ThreadId: %lu\n",
                GetCurrentThreadId()
            );

            fflush(stdout);
        };

    printf("================================\n");
    printf(" APC Non-Alertable Test\n");
    printf("================================\n");
    printf("Process ID   : %lu\n", pid);
    printf("Thread ID    : %lu\n", tid);
    printf("APC Callback : %p\n",
        reinterpret_cast<void*>(UserApcCallback));
    printf("Alertable    : FALSE\n");
    printf("================================\n");

    fflush(stdout);

    // 무한 루프: Alertable Wait 사용하지 않음
    while (TRUE)
    {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid
        );

        if (hProcess != NULL)
        {
            CloseHandle(hProcess);
        }
    }

    return 0;
}