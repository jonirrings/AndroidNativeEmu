import logging
import posixpath
import sys

from unicorn import UcError, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE
from unicorn.arm_const import *

from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

import debug_utils

IJM_CRYPTO_LICENSE_KEY = "C0612E92E4F99FA8A1C73EB94" \
                         "D3969F2D094476F4DC16620AF" \
                         "850ACCDB9DA2D3024796E1A65" \
                         "AEBE504235D04E85520391E7B" \
                         "694D83C7F58C2C70C3E90E81C" \
                         "B70A97F6855F40243F5852E04" \
                         "D013DBC263984BBF58F8F9EFB" \
                         "BA59C9E51E50AF320E6BD"


# Create java class.
class MainActivity(metaclass=JavaClassDef, jvm_name='com.csair.mbp.CSMBPApplication/me.cryptor.MainActivity'):

    def __init__(self):
        pass

    @java_method_def(name='setKey', signature='()Ljava/lang/String;', native=True)
    def setKey(self, strKey):
        pass

    def test(self):
        pass


# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfp_inst_set=True,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
)

# emulator.uc.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
# emulator.uc.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)

# Register Java class.
emulator.java_classloader.add_class(MainActivity)

# Load all libraries.
emulator.load_library("example_binaries/32/libdl.so")
emulator.load_library("example_binaries/32/libc.so")
emulator.load_library("example_binaries/32/libstdc++.so")
emulator.load_library("example_binaries/32/libm.so")
lib_module = emulator.load_library("example_binaries/32/libJMEncryptBox.so")

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("=> 0x%08x - %s" % (module.base, module.filename))

# Debug
# emulator.uc.hook_add(UC_HOOK_CODE, debug_utils.hook_code)
# emulator.uc.hook_add(UC_HOOK_MEM_UNMAPPED, debug_utils.hook_unmapped)
# emulator.uc.hook_add(UC_HOOK_MEM_WRITE, debug_utils.hook_mem_write)
# emulator.uc.hook_add(UC_HOOK_MEM_READ, debug_utils.hook_mem_read)

try:
    # Run JNI_OnLoad.
    #   JNI_OnLoad will call 'RegisterNatives'.
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)

    # Do native stuff.
    main_activity = MainActivity()
    logger.info("Response from setKey JNI call: %s" % main_activity.setKey(emulator, IJM_CRYPTO_LICENSE_KEY))

    # Dump natives found.
    logger.info("Exited EMU.")
    logger.info("Native methods registered to MainActivity:")

    for method in MainActivity.jvm_methods.values():
        if method.native:
            logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))
except UcError as e:
    print("Exit at %x" % emulator.uc.reg_read(UC_ARM_REG_PC))
    raise
