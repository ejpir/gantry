set +e
python3 - <<'PY'
import fcntl, struct, os
def _IOC(d,t,nr,sz): return (d<<30)|(sz<<16)|(t<<8)|nr   # FIXED: size at bit 16
CREATE_VM=_IOC(0,0xAE,0x01,0)
CREATE_VCPU=_IOC(0,0xAE,0x41,0)
VCPU_INIT=_IOC(1,0xAE,0xAE,32)
CREATE_DEVICE=_IOC(3,0xAE,0xE0,12)   # == 0xC00CAEE0
SET_DEV_ATTR=_IOC(1,0xAE,0xE1,16)
print('CREATE_DEVICE = %#x' % CREATE_DEVICE)
kfd=os.open('/dev/kvm',os.O_RDWR)
def fresh_vm(): return fcntl.ioctl(kfd,CREATE_VM,0)
def try_gic(vm,label):
    try:
        r=fcntl.ioctl(vm,CREATE_DEVICE,struct.pack('III',5,0,0),True)
        gfd=struct.unpack('III',r)[1]
        print(f'{label}: OK gic-fd={gfd}'); return gfd
    except OSError as e:
        print(f'{label}: errno={e.errno} {e.strerror}'); return None
try_gic(fresh_vm(),'P1: 0 vcpus          ')
vm=fresh_vm(); fcntl.ioctl(vm,CREATE_VCPU,0)
g=try_gic(vm,'P2: 1 vcpu, no init ')
if g:
    def setattr32(group,attr,val,label):
        da=struct.pack('IIQQ',0,group,attr,0)
        import ctypes
        v=ctypes.c_uint64(val)
        da=struct.pack('IIQQ',0,group,attr,ctypes.addressof(v))
        try:
            fcntl.ioctl(g,SET_DEV_ATTR,da); print(f'  attr {label}: OK')
        except OSError as e: print(f'  attr {label}: errno={e.errno} {e.strerror}')
    setattr32(3,0,192,'NR_IRQS=192')
    setattr32(0,0,0x08000000,'DIST@0x8000000')
    setattr32(0,1,0x080A0000,'REDIST@0x80A0000')
    setattr32(4,0,0,'CTRL_INIT')
    vc=fcntl.ioctl(vm,CREATE_VCPU,1)
    try:
        fcntl.ioctl(vc,VCPU_INIT,struct.pack('I7I',0,3,0,0,0,0,0,0)); print('  VCPU_INIT(1): OK')
    except OSError as e: print('  VCPU_INIT(1): errno=%d %s' % (e.errno,e.strerror))
PY
