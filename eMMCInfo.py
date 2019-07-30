import os
import re
import argparse
import subprocess

g_ext_csd_rev = 0

def run_cmd(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (out, err) = p.communicate()
    if err:
        return bytes.decode(err)
    return bytes.decode(out)


def hex_to_bin(s):
    return ''.join([format(int(c, 16), '04b') for c in s])


def bin_to_hex(s):
    return ''.join(format(int(h, 2), 'x') for h in re.findall(r'.{4}', s))


def get_linux_version(f):
    version = run_cmd('adb shell "cat /proc/version"')
    if version != None or len(version) != 0:
        f.write(version)
        f.write('\n')


emmc_cid = {'[MID]' : {'name' : 'Manufacturer ID',       'width' : 8},
            '[0]'   : {'name' : 'Reserved',              'width' : 6},
            '[CBX]' : {'name' : 'Device/BGA',            'width' : 2},
            '[OID]' : {'name' : 'OEM/Application ID',    'width' : 8},
            '[PNM]' : {'name' : 'Product name',          'width' : 48},
            '[PRV]' : {'name' : 'Product revision',      'width' : 8},
            '[PSN]' : {'name' : 'Product serial number', 'width' : 32},
            '[MDT]' : {'name' : 'Manufacturing date',    'width' : 8},
            '[CRC]' : {'name' : 'CRC7 checksum',         'width' : 7},
            '[1]'   : {'name' : 'not used, always 1',    'width' : 1}}


def decode_emmc_cid(cid):
    cid_b = hex_to_bin(cid)
    end = 0

    for k, v in emmc_cid.items():
        width = v['width']
        start = end
        end = start + width
        value = cid_b[start:end]
        if k == '[CBX]':
            device_types = ['Device (removable)', 'BGA (Discrete embedded)', 'POP', 'Reserved']
            value = device_types[int(value, 2)]
        elif k == '[PNM]':
            hs = bin_to_hex(value)
            value = bytes.fromhex(hs).decode('ascii')
        elif k == '[PRV]':
            value = str(int(value[0:4], 2)) + '.' + str(int(value[4:8], 2))
        elif k == '[MDT]':
            month = ['None', 'January', 'February', 'March', 'April', 'May', 'June',
                     'July', 'August', 'September', 'October', 'November', 'December']
            m = int(value[0:4], 2)
            y = int(value[4:8], 2) + 1997
            if g_ext_csd_rev > 4 and y < 2010:
                y += 16
            value = month[m] + ' ' + str(y)
        else:
            value = hex(int(value, 2))

        v.update({'value' : value})

    if end != 128:
        print('[cid] %d != 128' % end)


def write_emmc_cid(f, cid):
    f.write('-> cid: ' + cid + '\n')
    decode_emmc_cid(cid)
    for k, v in emmc_cid.items():
        s = k + ' ' + v['name'] + '<' + str(v['width']) + '>' + ': ' + v['value'] + '\n'
        f.write(s)
    f.write('\n')


def get_emmc_cid(f):
    cid = run_cmd('adb shell "cat /sys/class/block/mmcblk0/device/cid"')
    if cid != None or len(cid) != 0:
        write_emmc_cid(f, cid)


emmc_csd = {'[CSD_STRUCTURE]'      : {'name'  : 'CSD structure',
                                      'width' : 2,
                                      'type'  : 'R'},
            '[SPEC_VERS]'          : {'name'  : 'System specification version',
                                      'width' : 4,
                                      'type'  : 'R'},
            '[Reserved2]'          : {'name'  : 'Reserved',
                                      'width' : 2,
                                      'type'  : 'R'},
            '[TAAC]'               : {'name'  : 'Data read access-time 1',
                                      'width' : 8,
                                      'type'  : 'R'},
            '[NSAC]'               : {'name'  : 'Data read access-time 2 in CLK cycles (NSAC*100)',
                                      'width' : 8,
                                      'type'  : 'R'},
            '[TRAN_SPEED]'         : {'name'  : 'Max. bus clock frequency',
                                      'width' : 8,
                                      'type'  : 'R'},
            '[CCC]'                : {'name'  : 'Device command classes',
                                      'width' : 12,
                                      'type'  : 'R'},
            '[READ_BL_LEN]'        : {'name'  : 'Max. read data block length',
                                      'width' : 4,
                                      'type'  : 'R'},
            '[READ_BL_PARTIAL]'    : {'name'  : 'Partial blocks for read allowed',
                                      'width' : 1,
                                      'type'  : 'R'},
            '[WRITE_BLK_MISALIGN]' : {'name'  : 'Write block misalignment',
                                      'width' : 1,
                                      'type'  : 'R'},
            '[READ_BLK_MISALIGN]'  : {'name'  : 'Read block misalignment',
                                      'width' : 1,
                                      'type'  : 'R'},
            '[DSR_IMP]'            : {'name'  : 'DSR implemented',
                                      'width' : 1,
                                      'type'  : 'R'},
            '[Reserved1]'          : {'name'  : 'Reserved',
                                      'width' : 2,
                                      'type'  : 'R'},
            '[C_SIZE]'             : {'name'  : 'Device size',
                                      'width' : 12,
                                      'type'  : 'R'},
            '[VDD_R_CURR_MIN]'     : {'name'  : 'Max. read current @ VDD min',
                                      'width' : 3,
                                      'type'  : 'R'},
            '[VDD_R_CURR_MAX]'     : {'name'  : 'Max. read current @ VDD max',
                                      'width' : 3,
                                      'type'  : 'R'},
            '[VDD_W_CURR_MIN]'     : {'name'  : 'Max. write current @ VDD min',
                                      'width' : 3,
                                      'type'  : 'R'},
            '[VDD_W_CURR_MAX]'     : {'name'  : 'Max. write current @ VDD max',
                                      'width' : 3,
                                      'type'  : 'R'},
            '[C_SIZE_MULT]'        : {'name'  : 'Device size multiplier',
                                      'width' : 3,
                                      'type'  : 'R'},
            '[ERASE_GRP_SIZE]'     : {'name'  : 'Erase group size',
                                      'width' : 5,
                                      'type'  : 'R'},
            '[ERASE_GRP_MULT]'     : {'name'  : 'Erase group size multiplier',
                                      'width' : 5,
                                      'type'  : 'R'},
            '[WP_GRP_SIZE]'        : {'name'  : 'Write protect group size',                         
                                      'width' : 5,
                                      'type'  : 'R'},
            '[WP_GRP_ENABLE]'      : {'name'  : 'Write protect group enable',                       
                                      'width' : 1,
                                      'type'  : 'R'},
            '[DEFAULT_ECC]'        : {'name'  : 'Manufacturer default ECC',                         
                                      'width' : 2,
                                      'type'  : 'R'},
            '[R2W_FACTOR]'         : {'name'  : 'Write speed factor',                               
                                      'width' : 3,
                                      'type'  : 'R'},
            '[WRITE_BL_LEN]'       : {'name'  : 'Max. write data block length',                     
                                      'width' : 4,
                                      'type'  : 'R'},
            '[WRITE_BL_PARTIAL]'   : {'name'  : 'Partial blocks for write allowed',                 
                                      'width' : 1,
                                      'type'  : 'R'},
            '[Reserved0]'          : {'name'  : 'Reserved',                                         
                                      'width' : 4,
                                      'type'  : 'R'},
            '[CONTENT_PROT_APP]'   : {'name'  : 'Content protection application',                   
                                      'width' : 1,
                                      'type'  : 'R'},
            '[FILE_FORMAT_GRP]'    : {'name'  : 'File format group',                                
                                      'width' : 1,
                                      'type'  : 'R/W'},
            '[COPY]'               : {'name'  : 'Copy flag (OTP)',                                  
                                      'width' : 1,
                                      'type'  : 'R/W'},
            '[PERM_WRITE_PROTECT]' : {'name'  : 'Permanent write protection',                       
                                      'width' : 1,
                                      'type'  : 'R/W'},
            '[TMP_WRITE_PROTECT]'  : {'name'  : 'Temporary write protection',                       
                                      'width' : 1,
                                      'type'  : 'R/W/E'},
            '[FILE_FORMAT]'        : {'name'  : 'File format',                                      
                                      'width' : 2,
                                      'type'  : 'R/W'},
            '[ECC]'                : {'name'  : 'ECC code',                                         
                                      'width' : 2,
                                      'type'  : 'R/W/E'},
            '[CRC]'                : {'name'  : 'CRC',                                              
                                      'width' : 7,
                                      'type'  : 'R/W/E'},
            '[1]'                  : {'name'  : 'not used, always 1',                               
                                      'width' : 1,
                                      'type'  : '-'}}


def decode_emmc_csd(csd):
    csd_b = hex_to_bin(csd)
    end = 0

    for k, v in emmc_csd.items():
        width = v['width']
        start = end
        end = start + width
        value = csd_b[start:end]
        if k == '[CSD_STRUCTURE]':
            csd_struct = ['CSD version No. 1.0, Allocated by MMCA',
                          'CSD version No. 1.1, Allocated by MMCA',
                          'CSD version No. 1.2, Version 4.1–4.2–4.3-4.41-4.5-4.51-5.0-5.01-5.1',
                          'Version is coded in the CSD_STRUCTURE byte in the EXT_CSD register']
            value = csd_struct[int(value, 2)]
        elif k == '[SPEC_VERS]':
            temp = int(value, 2)
            if temp == 4:
                value = 'Version 4.1–4.2–4.3-4.4-4.41-4.5-4.51-5.0-5.01-5.1'
            elif temp < 4:
                value = 'Allocated by MMCA'
            else:
                value = 'Reserved'
        elif k == '[TAAC]':
            time_unit = ['1ns', '10ns', '100ns', '1us', '10us', '100us', '1ms', '10ms']
            multi_factor = ['reserved', '1.0', '1.2', '1.3', '1.5', '2.0', '2.5', '3.0', '3.5',
                            '4.0', '4.5', '5.5', '6.0', '7.0', '8.0']
            temp = int(value, 2)
            value = time_unit[temp&0x7] + ' * ' + multi_factor[(temp>>3)&0xf]
        elif k == '[TRAN_SPEED]':
            freq_unit = ['100KHz', '1MHz', '10MHz', '100MHz',
                         'reserved', 'reserved', 'reserved', 'reserved']
            multi_factor = ['reserved', '1.0', '1.2', '1.3', '1.5', '2.0', '2.5', '3.0', '3.6',
                            '4.0', '4.5', '5.5', '6.0', '7.0', '8.0']
            temp = int(value, 2)
            value = freq_unit[temp&0x7] + ' * ' + multi_factor[(temp>>3)&0xf]
        elif k == '[READ_BL_LEN]':
            if int(value, 2) == 15:
                value = 'Extension to EXT_CSD'
            else:
                value = str(1 << temp) + ' Bytes'
        elif k == '[VDD_R_CURR_MIN]' or k == '[VDD_W_CURR_MIN]':
            current = ['0.5mA', '1mA', '5mA', '10mA', '25mA', '35mA', '60mA', '100mA']
            value = current[int(value, 2)&0x7]
        elif k == '[VDD_R_CURR_MAX]' or k == '[VDD_W_CURR_MAX]':
            current = ['1mA', '5mA', '10mA', '25mA', '35mA', '45mA', '80mA', '200mA']
            value = current[int(value, 2)&0x7]
        elif k == '[C_SIZE_MULT]':
            value = str(1 << ((int(value, 2)&0x7) + 2))
        elif k == '[R2W_FACTOR]':
            value = str(1 << (int(value, 2)))
        elif k == '[FILE_FORMAT]':
            file_format = ['Hard disk-like file system with partition table',
                           'DOS FAT (floppy-like) with boot sector only (no partition table)',
                           'Universal File Format',
                           'Others / Unknown']
            value = file_format[int(value, 2)]
            if emmc_csd['[FILE_FORMAT_GRP]']['value'] == '0x1':
                value = 'Reserved'
        elif k == '[ECC]':
            ecc = ['None (default)', 'BCH (542, 512), level:3', 'Reserved', 'Reserved']
            value = ecc[int(value, 2)]
        else:
            value = hex(int(value, 2))

        v.update({'value' : value})

    if end != 128:
        print('[csd] %d != 128' % end)


def write_emmc_csd(f, csd):
    f.write('-> csd: ' + csd + '\n')
    decode_emmc_csd(csd)
    for k, v in emmc_csd.items():
        s = k + ' ' + v['name'] + '<' + str(v['width']) + '>' + '<' + v['type'] + '>' + ': ' + v['value'] + '\n'
        f.write(s)
    f.write('\n')


def get_emmc_csd(f):
    csd = run_cmd('adb shell "cat /sys/class/block/mmcblk0/device/csd"')
    if csd != None or len(csd) != 0:
        write_emmc_csd(f, csd)


emmc_ext_csd = {'[Reserved0]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 15,
                                                                 'type'   : 'TBD'},
                '[CMDQ_MODE_EN]'                              : {'name'   : 'Command Queue Mode Enable',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[SECURE_REMOVAL_TYPE]'                       : {'name'   : 'Secure Removal Type',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W & R'},
                '[PRODUCT_STATE_AWARENESS_ENABLEMENT]'        : {'name'   : 'Product state awareness enablement',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E & R'},
                '[MAX_PRE_LOADING_DATA_SIZE]'                 : {'name'   : 'Max pre loading data size',
                                                                 'size_B' : 4,
                                                                 'type'   : 'R'},
                '[PRE_LOADING_DATA_SIZE]'                     : {'name'   : 'Pre loading data size',
                                                                 'size_B' : 4,
                                                                 'type'   : 'R/W/E_P'},
                '[FFU_STATUS]'                                : {'name'   : 'FFU status',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved1]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 2,
                                                                 'type'   : 'TBD'},
                '[MODE_OPERATION_CODES]'                      : {'name'   : 'Mode operation codes',
                                                                 'size_B' : 1,
                                                                 'type'   : 'W/E_P'},
                '[MODE_CONFIG]'                               : {'name'   : 'Mode config',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[BARRIER_CTRL]'                              : {'name'   : 'Control to turn the Barrier ON/OFF',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W'},
                '[FLUSH_CACHE]'                               : {'name'   : 'Flushing of the cache',
                                                                 'size_B' : 1,
                                                                 'type'   : 'W/E_P'},
                '[CACHE_CTRL]'                                : {'name'   : 'Control to turn the Cache ON/OFF',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[POWER_OFF_NOTIFICATION]'                    : {'name'   : 'Power Off Notification',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[PACKED_FAILURE_INDEX]'                      : {'name'   : 'Packed command failure index',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PACKED_COMMAND_STATUS]'                     : {'name'   : 'Packed command status',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[CCONTEXT_CONF]'                             : {'name'   : 'Context configuration',
                                                                 'size_B' : 15,
                                                                 'type'   : 'R/W/E_P'},
                '[EXT_PARTITIONS_ATTRIBUTE]'                  : {'name'   : 'Extended Partitions Attribute',
                                                                 'size_B' : 2,
                                                                 'type'   : 'R/W'},
                '[EXCEPTION_EVENTS_STATUS]'                   : {'name'   : 'Exception events status',
                                                                 'size_B' : 2,
                                                                 'type'   : 'R'},
                '[EXCEPTION_EVENTS_CTRL]'                     : {'name'   : 'Exception events control',
                                                                 'size_B' : 2,
                                                                 'type'   : 'R/W/E_P'},
                '[DYNCAP_NEEDED]'                             : {'name'   : 'Number of addressed group to be Released',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[CLASS_6_CTRL]'                              : {'name'   : 'Class 6 commands control',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[INI_TIMEOUT_EMU]'                           : {'name'   : '1st initialization after disabling sector size emulation',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[DATA_SECTOR_SIZE]'                          : {'name'   : 'Sector size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[USE_NATIVE_SECTOR]'                         : {'name'   : 'Sector size emulation',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W'},
                '[NATIVE_SECTOR_SIZE]'                        : {'name'   : 'Native sector size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[VENDOR_SPECIFIC_FIELD]'                     : {'name'   : 'Vendor Specific Fields',
                                                                 'size_B' : 64,
                                                                 'type'   : 'vendor'},
                '[Reserved2]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 2,
                                                                 'type'   : 'TBD'},
                '[PROGRAM_CID_CSD_DDR_SUPPORT]'               : {'name'   : 'Program CID/CSD in DDR mode support',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PERIODIC_WAKEUP]'                           : {'name'   : 'Periodic Wake-up',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E'},
                '[TCASE_SUPPORT]'                             : {'name'   : 'Package Case Temperature is controlled',
                                                                 'size_B' : 1,
                                                                 'type'   : 'W/E_P'},
                '[PRODUCTION_STATE_AWARENESS]'                : {'name'   : 'Production state awareness',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E'},
                '[SEC_BAD_BLK_MGMNT]'                         : {'name'   : 'Bad Block Management mode',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W'},
                '[Reserved3]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[ENH_START_ADDR]'                            : {'name'   : 'Enhanced User Data Start Address',
                                                                 'size_B' : 4,
                                                                 'type'   : 'R/W'},
                '[ENH_SIZE_MULT]'                             : {'name'   : 'Enhanced User Data Area Size',
                                                                 'size_B' : 3,
                                                                 'type'   : 'R/W'},
                '[GP_SIZE_MULT]'                              : {'name'   : 'General Purpose Partition Size',
                                                                 'size_B' : 12,
                                                                 'type'   : 'R/W'},
                '[PARTITION_SETTING_COMPLETED]'               : {'name'   : 'Partitioning Setting',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W'},
                '[PARTITIONS_ATTRIBUTE]'                      : {'name'   : 'Partitions attribute',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W'},
                '[MAX_ENH_SIZE_MULT]'                         : {'name'   : 'Max Enhanced Area Size',
                                                                 'size_B' : 3,
                                                                 'type'   : 'R'},
                '[PARTITIONING_SUPPORT]'                      : {'name'   : 'Partitioning Support',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[HPI_MGMT]'                                  : {'name'   : 'HPI management',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[RST_n_FUNCTION]'                            : {'name'   : 'H/W reset function',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W'},
                '[BKOPS_EN]'                                  : {'name'   : 'Enable background operations handshake',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W & R/W/E'},
                '[BKOPS_START]'                               : {'name'   : 'Manually start background operations',
                                                                 'size_B' : 1,
                                                                 'type'   : 'W/E_P'},
                '[SANITIZE_START]'                            : {'name'   : 'Start Sanitize operation',
                                                                 'size_B' : 1,
                                                                 'type'   : 'W/E_P'},
                '[WR_REL_PARAM]'                              : {'name'   : 'Write reliability parameter register',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[WR_REL_SET]'                                : {'name'   : 'Write reliability setting register',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W'},
                '[RPMB_SIZE_MULT]'                            : {'name'   : 'RPMB Size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[FW_CONFIG]'                                 : {'name'   : 'FW configuration',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W'},
                '[Reserved4]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[USER_WP]'                                   : {'name'   : 'User area write protection register',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W,R/W/C_P & R/W/E_P'},
                '[Reserved5]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[BOOT_WP]'                                   : {'name'   : 'Boot area write protection register',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W & R/W/C_P'},
                '[BOOT_WP_STATUS]'                            : {'name'   : 'Boot write protection status registers',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[ERASE_GROUP_DEF]'                           : {'name'   : 'High-density erase group definition',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[Reserved6]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[BOOT_BUS_CONDITIONS]'                       : {'name'   : 'Boot bus Conditions',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E'},
                '[BOOT_CONFIG_PROT]'                          : {'name'   : 'Boot config protection',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W & R/W/C_P'},
                '[PARTITION_CONFIG]'                          : {'name'   : 'Partition configuration',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E & R/W/E_P'},
                '[Reserved7]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[ERASED_MEM_CONT]'                           : {'name'   : 'Erased memory content',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved8]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[BUS_WIDTH]'                                 : {'name'   : 'Bus width mode',
                                                                 'size_B' : 1,
                                                                 'type'   : 'W/E_P'},
                '[STROBE_SUPPORT]'                            : {'name'   : 'Strobe Support',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[HS_TIMING]'                                 : {'name'   : 'High-speed interface timing',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[Reserved9]'                                 : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[POWER_CLASS]'                               : {'name'   : 'Power class',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[Reserved10]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[CMD_SET_REV]'                               : {'name'   : 'Command set revision',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved11]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[CMD_SET]'                                   : {'name'   : 'Command set',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R/W/E_P'},
                '[EXT_CSD_REV]'                               : {'name'   : 'Extended CSD revision',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved12]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[CSD_STRUCTURE]'                             : {'name'   : 'CSD STRUCTURE',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved13]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[DEVICE_TYPE]'                               : {'name'   : 'Device type',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[DRIVER_STRENGTH]'                           : {'name'   : 'I/O Driver Strength',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[OUT_OF_INTERRUPT_TIME]'                     : {'name'   : 'Out-of-interrupt busy timing',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PARTITION_SWITCH_TIME]'                     : {'name'   : 'Partition switching timing',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PWR_CL_52_195]'                             : {'name'   : 'Power class for 52 MHz at 1.95 V 1 R',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PWR_CL_26_195]'                             : {'name'   : 'Power class for 26 MHz at 1.95 V 1 R',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PWR_CL_52_360]'                             : {'name'   : 'Power class for 52 MHz at 3.6 V 1 R',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PWR_CL_26_360]'                             : {'name'   : 'Power class for 26 MHz at 3.6 V 1 R',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved14]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[MIN_PERF_R_4_26]'                           : {'name'   : 'Minimum Read Performance for 4bit at 26 MHz',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[MIN_PERF_W_4_26]'                           : {'name'   : 'Minimum Write Performance for 4bit at 26 MHz',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[MIN_PERF_R_8_26_4_52]'                      : {'name'   : 'Minimum Read Performance for 8bit at 26 MHz, for 4bit at 52MHz',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[MIN_PERF_W_8_26_4_52]'                      : {'name'   : 'Minimum Write Performance for 8bit at 26 MHz, for 4bit at 52MHz',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[MIN_PERF_R_8_52]'                           : {'name'   : 'Minimum Read Performance for 8bit at 52 MHz',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[MIN_PERF_W_8_52]'                           : {'name'   : 'Minimum Write Performance for 8bit at52 MHz',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[SECURE_WP_INFO]'                            : {'name'   : 'Secure Write Protect Information',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[SEC_COUNT]'                                 : {'name'   : 'Sector Count',
                                                                 'size_B' : 4,
                                                                 'type'   : 'R'},
                '[SLEEP_NOTIFICATION_TIME]'                   : {'name'   : 'Sleep Notification Timout',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[S_A_TIMEOUT]'                               : {'name'   : 'Sleep/awake timeout',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PRODUCTION_STATE_AWARENESS_TIMEOUT]'        : {'name'   : 'Production state awareness timeout',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[S_C_VCCQ]'                                  : {'name'   : 'Sleep current (VCCQ)',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[S_C_VCC]'                                   : {'name'   : 'Sleep current (VCC)',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[HC_WP_GRP_SIZE]'                            : {'name'   : 'High-capacity write protect group size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[REL_WR_SEC_C]'                              : {'name'   : 'Reliable write sector count',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[ERASE_TIMEOUT_MULT]'                        : {'name'   : 'High-capacity erase timeout',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[HC_ERASE_GRP_SIZE]'                         : {'name'   : 'High-capacity erase unit size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[ACC_SIZE]'                                  : {'name'   : 'Access size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[BOOT_SIZE_MULT]'                            : {'name'   : 'Boot partition size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved15]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[BOOT_INFO]'                                 : {'name'   : 'Boot information',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[SEC_TRIM_MULT]'                             : {'name'   : 'Secure TRIM Multiplier',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[SEC_ERASE_MULT]'                            : {'name'   : 'Secure Erase Multiplier',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[SEC_FEATURE_SUPPORT]'                       : {'name'   : 'Secure Feature support',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[TRIM_MULT]'                                 : {'name'   : 'TRIM Multiplier',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved16]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[MIN_PERF_DDR_R_8_52]'                       : {'name'   : 'Minimum Read Performance for 8bit at 52MHz in DDR mode',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[MIN_PERF_DDR_W_8_52]'                       : {'name'   : 'Minimum Write Performance for 8bit at 52MHz in DDR mode',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PWR_CL_200_130]'                            : {'name'   : 'Power class for 200MHz, at VCCQ =1.3V, VCC = 3.6V',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PWR_CL_200_195]'                            : {'name'   : 'Power class for 200MHz at VCCQ =1.95V, VCC = 3.6V',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PWR_CL_DDR_52_195]'                         : {'name'   : 'Power class for 52MHz, DDR at VCC = 1.95V',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PWR_CL_DDR_52_360]'                         : {'name'   : 'Power class for 52MHz, DDR at VCC = 3.6V',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[CACHE_FLUSH_POLICY]'                        : {'name'   : 'Cache Flushing Policy',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[INI_TIMEOUT_AP]'                            : {'name'   : '1st initialization time after partitioning',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[CORRECTLY_PRG_SECTORS_NUM]'                 : {'name'   : 'Number of correctly programmed sectors',
                                                                 'size_B' : 4,
                                                                 'type'   : 'R'},
                '[BKOPS_STATUS]'                              : {'name'   : 'Background operations status',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[POWER_OFF_LONG_TIME]'                       : {'name'   : 'Power off notification(long) timeout',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[GENERIC_CMD6_TIME]'                         : {'name'   : 'Generic CMD6 timeout',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[CACHE_SIZE]'                                : {'name'   : 'Cache size',
                                                                 'size_B' : 4,
                                                                 'type'   : 'R'},
                '[PWR_CL_DDR_200_360]'                        : {'name'   : 'Power class for 200MHz, DDR at VCC= 3.6V',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[FIRMWARE_VERSION]'                          : {'name'   : 'Firmware version',
                                                                 'size_B' : 8,
                                                                 'type'   : 'R'},
                '[DEVICE_VERSION]'                            : {'name'   : 'Device version',
                                                                 'size_B' : 2,
                                                                 'type'   : 'R'},
                '[OPTIMAL_TRIM_UNIT_SIZE]'                    : {'name'   : 'Optimal trim unit size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[OPTIMAL_WRITE_SIZE]'                        : {'name'   : 'Optimal write size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[OPTIMAL_READ_SIZE]'                         : {'name'   : 'Optimal read size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[PRE_EOL_INFO]'                              : {'name'   : 'Pre EOL information',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[DEVICE_LIFE_TIME_EST_TYP_A]'                : {'name'   : 'Device life time estimation type A',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[DEVICE_LIFE_TIME_EST_TYP_B]'                : {'name'   : 'Device life time estimation type B',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[VENDOR_PROPRIETARY_HEALTH_REPORT]'          : {'name'   : 'Vendor proprietary health report',
                                                                 'size_B' : 32,
                                                                 'type'   : 'R'},
                '[NUMBER_OF_FW_SECTORS_CORRECTLY_PROGRAMMED]' : {'name'   : 'Number of FW sectors correctly programmed',
                                                                 'size_B' : 4,
                                                                 'type'   : 'R'},
                '[Reserved17]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 1,
                                                                 'type'   : 'TBD'},
                '[CMDQ_DEPTH]'                                : {'name'   : 'CMD Queuing Depth',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[CMDQ_SUPPORT]'                              : {'name'   : 'CMD Queuing Support',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved18]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 177,
                                                                 'type'   : 'TBD'},
                '[BARRIER_SUPPORT]'                           : {'name'   : 'Barrier support',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[FFU_ARG]'                                   : {'name'   : 'FFU Argument',
                                                                 'size_B' : 4,
                                                                 'type'   : 'R'},
                '[OPERATION_CODE_TIMEOUT]'                    : {'name'   : 'Operation codes timeout',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[FFU_FEATURES]'                              : {'name'   : 'FFU features',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[SUPPORTED_MODES]'                           : {'name'   : 'Supported modes',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[EXT_SUPPORT]'                               : {'name'   : 'Extended partitions attribute support',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[LARGE_UNIT_SIZE_M1]'                        : {'name'   : 'Large Unit size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[CONTEXT_CAPABILITIES]'                      : {'name'   : 'Context management capabilities',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[TAG_RES_SIZE]'                              : {'name'   : 'Tag Resources Size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[TAG_UNIT_SIZE]'                             : {'name'   : 'Tag Unit Size',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[DATA_TAG_SUPPORT]'                          : {'name'   : 'Data Tag Support',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[MAX_PACKED_WRITES]'                         : {'name'   : 'Max packed write commands',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[MAX_PACKED_READS]'                          : {'name'   : 'Max packed read commands',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[BKOPS_SUPPORT]'                             : {'name'   : 'Background operations support',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[HPI_FEATURES]'                              : {'name'   : 'HPI features',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[S_CMD_SET]'                                 : {'name'   : 'Supported Command Sets',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[EXT_SECURITY_ERR]'                          : {'name'   : 'Extended Security Commands Error',
                                                                 'size_B' : 1,
                                                                 'type'   : 'R'},
                '[Reserved19]'                                : {'name'   : 'Reserved',
                                                                 'size_B' : 6,
                                                                 'type'   : 'TBD'}}


def decode_emmc_ext_csd(ext_csd):
    end = 0
    global g_ext_csd_rev

    for k, v in emmc_cid.items():
        width = v['size_B'] * 2
        start = end
        end = start + width
        value = ext_csd[start:end]

        if k == '[EXT_CSD_REV]':
            g_ext_csd_rev = int(value, 16)

        v.update({'value' : '0x' + value})

    if (end/2) != 512:
        print('[ext_csd] %d != 512' %(end/2))


def write_emmc_ext_csd(f, ext_csd):
    f.write('-> ext_csd: ' + ext_csd + '\n')
    decode_emmc_ext_csd(ext_csd)
    for k, v in emmc_ext_csd.items():
        s = k + ' ' + v['name'] + '<' + str(v['size_B']) + '>' + ': ' + v['value'] + '\n'
        f.write(s)
    f.write('\n')


def get_emmc_ext_csd(f):
    ext_csd = run_cmd('adb shell "cat /sys/kernel/debug/mmc0/mmc0:0001/ext_csd"')
    if ext_csd != None or len(ext_csd) != 0:
        write_emmc_cid(f, ext_csd)


def init_args():
    parser = argparse.ArgumentParser(
        description = '''
                    Get eMMC Information, Python 3.5+ required
                    ''',
        formatter_class = argparse.RawTextHelpFormatter)
    parser.add_argument('-e', '--extcsd', type=str, default=None, help='ext-csd file path')
    parser.add_argument('-s', '--csd', type=str, default=None, help='csd file path')
    parser.add_argument('-i', '--cid', type=str, default=None, help='cid file path')
    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = init_args()
    report = 'eMMCInfo.txt'
    use_adb_shell = True

    if os.path.exists(report):
        os.remove(report)

    if args.extcsd or args.csd or args.cid:
        use_adb_shell = False

    with open(report, 'a+') as f:
        if use_adb_shell:
            get_linux_version(f)
            get_emmc_ext_csd(f)
            get_emmc_cid(f)
            get_emmc_csd(f)
        else:
            if args.extcsd:
                fargs = open(args.extcsd, 'r')
                ext_csd = fargs.readline().strip('\n')
                write_emmc_ext_csd(f, ext_csd)
                fargs.close()

            if args.cid:
                fargs = open(args.cid, 'r')
                cid = fargs.readline().strip('\n')
                write_emmc_cid(f, cid)
                fargs.close()

            if args.csd:
                fargs = open(args.csd, 'r')
                csd = fargs.readline().strip('\n')
                write_emmc_csd(f, csd)
                fargs.close()

        