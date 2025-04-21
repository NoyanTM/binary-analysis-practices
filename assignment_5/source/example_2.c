/*
book CheckForCCBreakpoint(void* pMemory, size_t SizeToCheck)
{
    unsigned char *pTmp - (unsigned char*)pMemory;
    for(size_t i = 0; i < SizeToCheck; i++)
    {
        if(pTmp[i] == 0xCC)
            return true;
    }
    return false
}
*/
