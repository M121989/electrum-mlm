# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import os
import threading

from . import util
from . import bitcoin
from . import constants
from .bitcoin import *

MAX_TARGET = 0x00000FFFFFFF0000000000000000000000000000000000000000000000000000
PREMINE1 =   0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

try:        
    from x17_hash import x17_gethash
except ImportError:        
    raise Exception("Error: x17_hash not available")

def serialize_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s

def deserialize_header(s, height):
    if not s:
        raise Exception('Invalid header: {}'.format(s))
    if len(s) != 80:
        raise Exception('Invalid header length: {}'.format(len(s)))
    hex_to_int = lambda s: int('0x' + bh2u(s[::-1]), 16)
    h = {}
    h['version'] = hex_to_int(s[0:4])
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = hex_to_int(s[68:72])
    h['bits'] = hex_to_int(s[72:76])
    h['nonce'] = hex_to_int(s[76:80])
    h['block_height'] = height
    return h

def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(Hash(bfh(serialize_header(header))))

def pow_hash_header(header):
     if header is None:
         return '0' * 64
     if header.get('prev_block_hash') is None:
         header['prev_block_hash'] = '00'*32
     return hash_encode(x17_gethash(bfh(serialize_header(header))))

blockchains = {}

def read_blockchains(config):
    blockchains[0] = Blockchain(config, 0, None)
    fdir = os.path.join(util.get_headers_dir(config), 'forks')
    if not os.path.exists(fdir):
        os.mkdir(fdir)
    l = filter(lambda x: x.startswith('fork_'), os.listdir(fdir))
    l = sorted(l, key = lambda x: int(x.split('_')[1]))
    for filename in l:
        checkpoint = int(filename.split('_')[2])
        parent_id = int(filename.split('_')[1])
        b = Blockchain(config, checkpoint, parent_id)
        h = b.read_header(b.checkpoint)
        if b.parent().can_connect(h, check_height=False):
            blockchains[b.checkpoint] = b
        else:
            util.print_error("cannot connect", filename)
    return blockchains

def check_header(header):
    if type(header) is not dict:
        return False
    for b in blockchains.values():
        if b.check_header(header):
            return b
    return False

def can_connect(header):
    for b in blockchains.values():
        if b.can_connect(header):
            return b
    return False


class Blockchain(util.PrintError):
    """
    Manages blockchain headers and their verification
    """
    def __init__(self, config, checkpoint, parent_id):
        self.config = config
        self.catch_up = None # interface catching up
        self.checkpoint = checkpoint
        self.checkpoints = constants.net.CHECKPOINTS
        self.parent_id = parent_id
        self.lock = threading.Lock()
        with self.lock:
            self.update_size()

    def parent(self):
        return blockchains[self.parent_id]

    def get_max_child(self):
        children = list(filter(lambda y: y.parent_id==self.checkpoint, blockchains.values()))
        return max([x.checkpoint for x in children]) if children else None

    def get_checkpoint(self):
        mc = self.get_max_child()
        return mc if mc is not None else self.checkpoint

    def get_branch_size(self):
        return self.height() - self.get_checkpoint() + 1

    def get_name(self):
        return self.get_hash(self.get_checkpoint()).lstrip('00')[0:10]

    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self.get_hash(height)

    def fork(parent, header):
        checkpoint = header.get('block_height')
        self = Blockchain(parent.config, checkpoint, parent.checkpoint)
        open(self.path(), 'w+').close()
        self.save_header(header)
        return self

    def height(self):
        return self.checkpoint + self.size() - 1

    def size(self):
        with self.lock:
            return self._size

    def update_size(self):
        p = self.path()
        self._size = os.path.getsize(p)//80 if os.path.exists(p) else 0

    def verify_header(self, header, prev_hash, target, height = 0):
        _hash = hash_header(header)
        if prev_hash != header.get('prev_block_hash'):
            util.print_error("!!!!111")
            raise Exception("prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash')))
        if constants.net.TESTNET:
            return
        bits = self.target_to_bits(target)
        if bits != header.get('bits'):
            util.print_error("bits mismatch: %s vs %s height: %d" % (bits, header.get('bits'),height))
            raise Exception("bits mismatch: %s vs %s height: %d" % (bits, header.get('bits'),height))

        _hashpow = pow_hash_header(header)

        if int('0x' + _hashpow, 16) > target:
            raise Exception("insufficient proof of work: %04X/%04X vs target %04X" % (int('0x' + _hashpow, 16),int('0x' + _hash, 16), target))

    def verify_chunk(self, index, data):
        num = len(data) // 80
        height = 2016 * index;
        prev_hash = self.get_hash(height - 1)

        headers = {}

        for i in range(num):
            raw_header = data[i*80:(i+1) * 80]
            header = deserialize_header(raw_header, height)

            headers[height] = header

            target = self.get_target(height, headers)

            self.verify_header(header, prev_hash, target, height)
            prev_hash = hash_header(header)

            height += 1

    def path(self):
        d = util.get_headers_dir(self.config)
        filename = 'blockchain_headers' if self.parent_id is None else os.path.join('forks', 'fork_%d_%d'%(self.parent_id, self.checkpoint))
        return os.path.join(d, filename)

    def save_chunk(self, index, chunk):
        filename = self.path()
        d = (index * 2016 - self.checkpoint) * 80
        if d < 0:
            chunk = chunk[-d:]
            d = 0
        truncate = index >= len(self.checkpoints)
        self.write(chunk, d, truncate)
        self.swap_with_parent()

    def swap_with_parent(self):
        if self.parent_id is None:
            return
        parent_branch_size = self.parent().height() - self.checkpoint + 1
        if parent_branch_size >= self.size():
            return
        self.print_error("swap", self.checkpoint, self.parent_id)
        parent_id = self.parent_id
        checkpoint = self.checkpoint
        parent = self.parent()
        self.assert_headers_file_available(self.path())
        with open(self.path(), 'rb') as f:
            my_data = f.read()
        self.assert_headers_file_available(parent.path())
        with open(parent.path(), 'rb') as f:
            f.seek((checkpoint - parent.checkpoint)*80)
            parent_data = f.read(parent_branch_size*80)
        self.write(parent_data, 0)
        parent.write(my_data, (checkpoint - parent.checkpoint)*80)
        # store file path
        for b in blockchains.values():
            b.old_path = b.path()
        # swap parameters
        self.parent_id = parent.parent_id; parent.parent_id = parent_id
        self.checkpoint = parent.checkpoint; parent.checkpoint = checkpoint
        self._size = parent._size; parent._size = parent_branch_size
        # move files
        for b in blockchains.values():
            if b in [self, parent]: continue
            if b.old_path != b.path():
                self.print_error("renaming", b.old_path, b.path())
                os.rename(b.old_path, b.path())
        # update pointers
        blockchains[self.checkpoint] = self
        blockchains[parent.checkpoint] = parent

    def assert_headers_file_available(self, path):
        if os.path.exists(path):
            return
        elif not os.path.exists(util.get_headers_dir(self.config)):
            raise FileNotFoundError('Electrum headers_dir does not exist. Was it deleted while running?')
        else:
            raise FileNotFoundError('Cannot find headers file but headers_dir is there. Should be at {}'.format(path))

    def write(self, data, offset, truncate=True):
        filename = self.path()
        with self.lock:
            self.assert_headers_file_available(filename)
            with open(filename, 'rb+') as f:
                if truncate and offset != self._size*80:
                    f.seek(offset)
                    f.truncate()
                f.seek(offset)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            self.update_size()

    def save_header(self, header):
        delta = header.get('block_height') - self.checkpoint
        data = bfh(serialize_header(header))
        assert delta == self.size()
        assert len(data) == 80
        self.write(data, delta*80)
        self.swap_with_parent()

    def read_header(self, height):
        assert self.parent_id != self.checkpoint
        if height < 0:
            return
        if height < self.checkpoint:
            return self.parent().read_header(height)
        if height > self.height():
            return
        delta = height - self.checkpoint
        name = self.path()
        self.assert_headers_file_available(name)
        with open(name, 'rb') as f:
            f.seek(delta * 80)
            h = f.read(80)
            if len(h) < 80:
                raise Exception('Expected to read a full header. This was only {} bytes'.format(len(h)))
        if h == bytes([0])*80:
            return None
        return deserialize_header(h, height)

    def get_hash(self, height):
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return constants.net.GENESIS
        elif height < len(self.checkpoints) * 2016:
            assert (height+1) % 2016 == 0, height
            index = height // 2016
            h, t = self.checkpoints[index]
            return h
        else:
            return hash_header(self.read_header(height))

    def get_header(self, height, headers=None):
        if headers is None:
            headers = {}

        return headers[height] if height in headers else self.read_header(height)


    def get_lwma_target(self, height, headers):
        cur = self.get_header(height, headers)
        last_height = (height - 1)
        last = self.get_header(last_height, headers)

        N = 30
        T = 150

        adjust = pow(0.9989, int(500 / N))
        k = int((N+1)/2) * adjust * T

        total = 0
        t = 0
        j = 0
        divkn = int(k * N * N)

        for i in range(height - N, height):
            cur = self.get_header(i, headers)
            prev_height = (i - 1)
            prev = self.get_header(prev_height, headers)

            solvetime = cur.get('timestamp') - prev.get('timestamp')
            if solvetime > 7 * T:
               solvetime = 7 * T
            if solvetime < -7 * T:
               solvetime = -(7 * T)

            j += 1
            t += solvetime * j
            target = self.bits_to_target(cur.get('bits'))

            total += (target // divkn)


        if t < 1:
           t = 1

        new_target = t * total

        if new_target > MAX_TARGET:
            new_target = MAX_TARGET

        return new_target

    def get_target(self, height, headers=None):
        if headers is None:
           headers = {}

        if constants.net.TESTNET:
            return 0
        if height == 0:
            return MAX_TARGET;
        if height < len(self.checkpoints):
            h, t = self.checkpoints[height]
            return t
        if height <= 210000:
            return PREMINE1;

        if height >= 256350:
            return self.get_lwma_target(height,headers)

        # old bitcoin
        lastheight = height - 1
        last = self.get_header(lastheight, headers)

        if height % 2016 == 0:
            first = self.get_header(height - 2016)
            target = self.bits_to_target(last.get('bits'))

            if height == 211680: 
                return self.bits_to_target(0x1e0ca63b)
            if height == 213696: 
                return self.bits_to_target(0x1e062a7b)

            nTargetTimespan = 14 * 24 * 60 * 60

            nActualTimespan = last.get('timestamp') - first.get('timestamp')

            if nActualTimespan < nTargetTimespan // 4:
                nActualTimespan = nTargetTimespan // 4

            if nActualTimespan > nTargetTimespan * 4:
                nActualTimespan = nTargetTimespan * 4

            target *= nActualTimespan 
            new_target = target // nTargetTimespan


            if (new_target > MAX_TARGET):
                new_target = MAX_TARGET

            return new_target
        else: 
            return self.bits_to_target(last.get('bits'))

    def bits_to_target(self, bits):
        size = bits >> 24
        word = bits & 0x007fffff

        if size <= 3:
            word >>= 8 * (3 - size)
            ret = word
        else:
            ret = word
            ret <<= 8 * (size - 3)

        return ret

    def target_to_bits(self, target):
        nbits = target.bit_length()
        # Round up to next 8-bits
        nbits = ((nbits + 7) & ~0x7)
        exponent = (int(nbits/8) & 0xff)
        coefficient = (target >> (nbits - 24)) & 0xffffff
        if coefficient & 0x800000:
             coefficient >>= 8
             exponent += 1
        return (exponent << 24) | coefficient

    def can_connect(self, header, check_height=True):
        if header is None:
            self.print_error("header error")
            return False
        height = header['block_height']
        if check_height and self.height() != height - 1:
            return False
        if height == 0:
            return hash_header(header) == constants.net.GENESIS
        try:
            prev_hash = self.get_hash(height - 1)
        except:
            return False
        if prev_hash != header.get('prev_block_hash'):
            return False
        target = self.get_target(height)
        try:
            self.verify_header(header, prev_hash, target, height)
        except BaseException as e:
            return False
        return True

    def connect_chunk(self, idx, hexdata):
        try:
            data = bfh(hexdata)
            self.verify_chunk(idx, data)
            #self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx, data)
            return True
        except BaseException as e:
            self.print_error('verify_chunk %d failed'%idx, str(e))
            return False

    def get_checkpoints(self):
        # for each chunk, store the hash of the last block and the target after the chunk
        cp = []
        n = self.height() // 2016
        for index in range(n):
            h = self.get_hash((index+1) * 2016 -1)
            target = self.get_target(index)
            cp.append((h, target))
        return cp
