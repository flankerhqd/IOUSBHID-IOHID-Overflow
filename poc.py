import kitlib
h = kitlib.openMultipleSvc('IOUSBHostHIDDevice', [0,0])[1]
kitlib.callConnectMethod(h, 12, [0x80000000L]*3, '', 0, 1)