import idaapi
import ida_segment
import ida_xref
import idc

# typedef const struct _s_RTTICompleteObjectLocator    
# {
#     unsigned long signature;
#     unsigned long offset;
#     unsigned long cdOffset;
#     int           pTypeDescriptor;
#     int           pClassDescriptor;
#     int           pSelf;
# } _RTTICompleteObjectLocator;

def get_vmt_methods(vtable):
    methods = []

    method_offset = get_ptr_size() 
    method = idaapi.get_64bit(vtable + method_offset)
    while idaapi.is_loaded(method) and idaapi.getseg(method).type == ida_segment.SEG_CODE:
        methods.append(method)
        method = idaapi.get_64bit(vtable + method_offset)
        method_offset += get_ptr_size()

    return methods

def get_ptr_size():
    return idaapi.inf_is_64bit() and 8 or 4

def find_rtti_col(segment: ida_segment.segment_t):
    RTTI_COL_SIZE = 24

    for i in range(segment.start_ea, segment.end_ea):
        SIGNATURE_VALUE = 1

        if (idaapi.get_32bit(i) != SIGNATURE_VALUE):
            continue

        COL_IMAGE_BASE_OFFSET = 20
        col_image_base_offset = idaapi.get_32bit(i + COL_IMAGE_BASE_OFFSET)
        if (col_image_base_offset == 0):
            continue

        TYPE_DESCRIPTOR_OFFSET = 12
        type_descriptor_offset = idaapi.get_32bit(i + TYPE_DESCRIPTOR_OFFSET)
        if (type_descriptor_offset == 0):
            continue

        CLASS_DESCRIPTOR_OFFSET = 16
        class_descriptor_offset = idaapi.get_32bit(i + CLASS_DESCRIPTOR_OFFSET)
        if (class_descriptor_offset == 0):
            continue
        
        image_base = i - col_image_base_offset
        type_descriptor_ptr = image_base + type_descriptor_offset
        class_descriptor_ptr = image_base + class_descriptor_offset
        class_descriptor_signature = idaapi.get_32bit(class_descriptor_ptr)
        if (class_descriptor_signature != 0):
            continue

        spare = idaapi.get_32bit(type_descriptor_ptr + 8)
        if (spare != 0):
            continue

        name = idaapi.get_strlit_contents(type_descriptor_ptr + 16, idaapi.get_max_strlit_length(type_descriptor_ptr + 16, idaapi.STRTYPE_C), idaapi.STRTYPE_C)
        if name is None: 
            continue

        vft = ida_xref.get_first_dref_to(i)
        methods = get_vmt_methods(vft)

        # for whatever the fuck reason idc.demangle_name doesn't work for this and im too lazy to implement a proper demangler so eh yea here we go for now :3
        name = str(name)
        name = name.replace("b\'.?", "").replace("\'", "").replace("AV", "").replace("?", "").replace("<", "").replace(">", "")
        
        renamed_methods = set()
        for method in methods:
            if (method in renamed_methods):
                continue

            idaapi.set_name(method, f"{name}::{idc.get_func_name(method)}")
            renamed_methods.add(method)

        i += RTTI_COL_SIZE

def run():
    for i in range(ida_segment.get_segm_qty()):
        segment: ida_segment.segment_t = ida_segment.getnseg(i);
        if (segment.type == ida_segment.SEG_DATA):
            find_rtti_col(segment)

class Plugin(idaapi.plugin_t):
    wanted_name = 'MSVC RTTI Parser'
    wanted_hotkey = ''
    comment = ''
    help = ''
    flags = 0

    def init(self):
        return idaapi.PLUGIN_OK
    
    def run(self):
        run()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return Plugin() 


if __name__ == '__main__':
    run()