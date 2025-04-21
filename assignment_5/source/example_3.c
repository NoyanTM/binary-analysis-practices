/*
int CheckHardwareBreakpoints()
{
    unsigned int NumBps = 0;
    
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(CONTEXT));

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();

    if(GetThreadContext(hThread, &ctx) == 0)
        return -1;
    
    if(ctx.Dr0 != 0)
        ++NumBps;
    if(ctx.Dr1 != 0)
        ++NumBps;
    if(ctx.Dr2 != 0)
        ++NumBps;
    if(ctx.Dr3 != 0)
        ++NumBps;
    
    return NumBps;
}
*/
