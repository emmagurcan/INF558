#!/usr/bin/env python3
"""
Tools for cryptanalyis of (monoalphabetic) substitution ciphers
author: Benjamin Smith (smith@lix.polytechnique.fr)
author: François Morain (morain@lix.polytechnique.fr)
version: 1.0

Based on François Morain's X3A INF558/INF568 tutorial
"""

import random
from collections import Counter
import itertools
import operator
import cmd
import pandas
pandas.set_option('display.max_columns', None)
import IPython.display

ct_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
pt_alphabet = 'abcdefghijklmnopqrstuvwxyz'
pt_vowels = 'aeiouy'

# valid_users = ('padawan', 'jedi', 'master', 'yoda')

def sorted_by_freq(iterable, freq):
    """sorted by frequency in dict/Counter freq (most frequent first)."""
    return sorted(iterable, key=lambda x: -freq[x])

def sorted_by_1(iterable):
    """sorted by their second components in descending order."""
    return sorted(iterable, key=operator.itemgetter(1), reverse=True)

class Language:
    """Data and tools for a given language.

    Data attributes:
        - vowels = ['a', 'e', 'i', 'o', 'u', 'y']
        - frequency = { i: freq(chr(i)) in language }
        - bigram = { (i,j): freq(chr(i)chr(j)) in language }
    """
    def __init__(self, lg):
        if lg not in ['fr', 'en', 'de', 'es']:
            print(f'Sorry, unknown language: {lg}')
            return
        self.lg = lg
        self._freq_filename = f'./Data/{lg}/freq.data'
        self._bigr_filename = f'./Data/{lg}/bigrammes.data'
        # Load frequencies
        with open(self._freq_filename, 'r') as fd:
            self.frequency = dict((x, float(fx)) for (x,fx) in (s.strip().split() for s in fd))
        # Ensure no bigrams are nonexistent: lets us iterate over bigrams
        self.bigram = dict.fromkeys(itertools.product(pt_alphabet, pt_alphabet), 0)
        self.transition_prob = {}
        with open(self._bigr_filename, 'r') as fd:
            for s in fd:  # s = "a ....."
                t = s.strip().split( )  # t = ['a', '0.00033', ...]
                (x, x_trans) = (t[0], list(zip(pt_alphabet, map(float, t[1:]))))
                x_tot = sum(p for (y, p) in x_trans)
                self.bigram.update(((x,y), fxy) for (y, fxy) in x_trans)
                if x_tot!=0:
                    self.transition_prob.update(((x,y), fxy/x_tot) for (y, fxy) in x_trans)
                else:
                    self.transition_prob.update(((x,y), 0.) for (y, fxy) in x_trans)                    

class Solver:
    def __init__(self, filename, language, user='padawan'):
        with open(filename, 'r') as f:
            self.msg = f.read( ).replace('\n', '')
            self.msg_freq = Counter(dict.fromkeys(ct_alphabet, 0))  # Force any absent symbols to 0
            self.msg_freq.update(self.msg)
            self.msg_bigram = Counter(dict.fromkeys(itertools.product(ct_alphabet, ct_alphabet), 0))
            self.msg_bigram.update(zip(self.msg[:-1], self.msg[1:]))
        self.lg = Language(language)
        self.user = user
        self.alph = dict.fromkeys(ct_alphabet, '-')  # Empty key

    def key_string(self):
        """A string representation of the current (partial) decryption key."""
        return (f'Cipher: {ct_alphabet}\n'
                f'Clear : {"".join(self.alph[x] for x in ct_alphabet)}')

    def set(self, C, p):
        """Map ciphertext symbol C to plaintext symbol p."""
        self.alph[C] = p

    def unset(self, C):
        """Unmap ciphertext symbol C (map to '-')."""
        self.alph[C] = '-'

    def decipher(self, block=50):
        """Decrypt the ciphertext using the current (partial) key."""
        return '\n'.join(f'{line}\n{"".join(self.alph[x] for x in line)}'
                     for line in (self.msg[i:i+block]
                                  for i in range(0, len(self.msg), block)))

    def map_to(self, cword, pword):
        """Set each symbol in cword to the corresponding symbol in pword."""
        self.alph.update(zip(cword, pword))

    def find_probable_word(self, w):
        """Construct a list of substrings of the ciphertext with the same geometry as w"""
        def geometry(w):
            return list(map(w.index, w))
        gw = geometry(w)
        return [ self.msg[i:i+len(w)] 
                for i in range(len(self.msg)-len(w)) 
                if geometry(self.msg[i:i+len(w)]) == gw]

    def gaines(self):
        """Gaines' consonant-line method"""
        lcontact = {x:[] for x in ct_alphabet}
        rcontact = {x:[] for x in ct_alphabet}
        for (x,y) in zip(self.msg[:-1],self.msg[1:]): # pairs of adjacent letters xy in self.msg
            # x is a left contact for y, y is a right contact for x
            lcontact[y].append(x)
            rcontact[x].append(y)
            # TODO: case of doubled letters
        l = sorted_by_1((x, len(set(lcontact[x] + rcontact[x]))) for x in ct_alphabet)
        # ready for establishing the line of consonants
        nbcontact = sum(ncx for (x, ncx) in l)
        threshold = int(nbcontact * 0.8)
        # print("nbcontact=", nbcontact, "threshold=", threshold)
        nb = 0
        cons = set()
        s = Counter()
        for (x, ncx) in l:
            nb += ncx
            if nb >= threshold:
                cons.add(x)
                s.update(lcontact[x] + rcontact[x])
        # ready for first amplification: looking for letters not appearing in
        # any contact with the "sure-fire" consonants
        cons.update(x for (x, ncx) in l if s[x] == 0)
        print(f'Suggested consonants: {" ".join(cons)}')
        print('Remaining letters:  ' +
              ' '.join(sorted_by_freq((x for x in ct_alphabet if x not in cons), s)))

    def sukhotin(self):
        """Sukhotin's method"""
        print("Sukhotin's method")
        c = Counter()
        for x in ct_alphabet:
            c[x] = sum(self.msg_bigram[x,y] + self.msg_bigram[y,x] for y in ct_alphabet if y != x)
        vowels = list()
        while len(vowels) < len(pt_vowels):
            (v, m) = c.most_common(1)[0]
            if m == 0:  # no more vowels
                break
            vowels.append(v)
            del c[v]
            c.subtract({x:2*(self.msg_bigram[x,v]+self.msg_bigram[v,x]) for x in c})
        return vowels

    def find_vowels(self):
        """Find vowels using Sukhotin's method."""
        ct_vowel_cands = sorted_by_freq(self.sukhotin(), self.msg_freq)
        print(f'Putative vowels:    {" ".join(ct_vowel_cands)}')
        print('   ' + ' '.join(f'{v:3}' for v in ct_vowel_cands))
        for v in ct_vowel_cands:
            print(f'{v}' + ' '.join(f'{self.msg_bigram[v,w]:3d}'
                                    for w in ct_vowel_cands))
        print('-'*len(pt_alphabet))
        true_vowels = sorted_by_freq(pt_vowels, self.lg.frequency)
        print('   ' + ' '.join(f'{v:3}' for v in true_vowels))
        n = len(self.msg)
        for v in true_vowels:
            print(f'{v}' + ' '.join(f'{int(n*self.lg.bigram[v,w]):3d}'
                                    for w in true_vowels))

    def optimize_vowels(self, lv):
        """try all permutations of vowels"""
        print('Minimal scores for all permutations of vowels')
        n = len(self.msg)
        def score(cand):
            return sum((self.msg_bigram[cv,cw]/n - self.lg.bigram[v,w])**2
                    for ((cv, v), (cw, w)) in itertools.product(zip(cand, pt_vowels), zip(cand, pt_vowels)))
        scored_perms = [(score(perm), perm) for perm in itertools.permutations(lv)]
        best = min(scored_perms)[1]
        return list(zip(best, pt_vowels))

    def optimize_consonants(self, alph):
        """OUTPUT: the alphabet maximizing the criterion"""
        consonants = ('l', 'n', 't', 's', 'r')
        # find frequent letters that are not classified yet
        tbc = sorted_by_freq((x for x in ct_alphabet if alph[x] == '-'), self.msg_freq)[:len(consonants)]
        # print(f'Most frequent unclassified letters: {" ".join(tbc)}')
        smax = 0
        for perm in itertools.permutations(tbc):
            alph.update(zip(perm, consonants))
            p = sum(self.lg.transition_prob[alph[x],alph[y]] 
                    for (x,y) in zip(self.msg[:-1],self.msg[1:])
                    if(alph[x] != '-' and alph[y] != '-'))
            if p > smax:
                # print(f'New transition prob = {p}')
                (smax, alphmax) = (p, alph.copy())
        return alphmax

    def find_qu(self, alph=None):
        """In some languages, qu obeys the same rules..."""
        if alph is None:
            alph = self.alph
        if self.lg.lg not in ('fr', 'es', 'it'):
            print('Rules only implemented for languages fr, es, it')
            return
        print('Trying to locate q and u')
        print('  candidate qu: times (notes)')  # [(u, now, occurrences)]')
        for (x, _) in self.msg_freq.most_common():
            ylist = list(y for y in ct_alphabet if self.msg_bigram[x,y] != 0)
            if 0 < len(ylist) <= 2:
                for y in ylist:
                    line = f'{x:>13}{y}: {self.msg_bigram[x,y]:<4}'
                    if alph[x] != '-':
                        line += f' ({x} now maps to {alph[x]})'
                    if alph[y] != '-':
                        line += f' ({y} now maps to {alph[y]})'
                    print(line)

    def auto(self):
        if self.user != 'padawan':
            return 
        alph = dict.fromkeys(ct_alphabet, '-')  # Empty key
        # fill in vowels
        lv = self.sukhotin()
        alph.update(self.optimize_vowels(lv))
        alph = self.optimize_consonants(alph)
        self.find_QU(alph)
        block = 50
        print('\n'.join(f'{line}\n{"".join(alph[x] for x in line)}'
                        for line in (self.msg[i:i+block]
                                     for i in range(0, len(self.msg), block))))
        print(f'From suggested key:\n'
              f'Cipher: {ct_alphabet}\n'
              f'Clear : {"".join(alph[x] for x in ct_alphabet)}')

    def report_frequencies(self):
        n = len(self.msg)
        sfreq_msg = self.msg_freq.most_common(20)
        sfreq_ref = sorted_by_1((x, int(n*self.lg.frequency[x])) for x in pt_alphabet)[:20]
        pad_msg = max(len(str(fx)) for (_, fx) in sfreq_msg)
        pad_ref = max(len(str(fx)) for (_, fx) in sfreq_ref)
        freq_raw = 'Symbol frequencies and percentages (top 20):\n'
        freq_raw += 'Ciphertext' + ' '*pad_msg + '| Plaintext language (normalized)\n'
        freq_raw += '\n'.join((f'{x} {fx:>{pad_msg}} {100*fx/n:>5.2f}'
                               '    '
                               f'{y} {fy:>{pad_ref}} {100*fy/n:>5.2f}')
                              for ((x,fx),(y,fy)) in zip(sfreq_msg, sfreq_ref))
        return freq_raw

    def report_bigrams(self):
        def bigram_table(freq, bigr):
            pad = max(len(str(v)) for v in bigr.values( ))
            res = '  '  + ' '.join(f'{x:<{pad}}' for x in freq) + '\n'
            res += '\n'.join(f'{x} ' + ' '.join(f'{(bigr[x,y] if bigr[x,y] else ""):<{pad}}'
                                                for y in freq)
                             for x in freq)
            return res
        sfreq = sorted_by_freq(ct_alphabet, self.msg_freq)
        res = 'Bigram frequencies in ciphertext:\n'
        res += bigram_table(sfreq, self.msg_bigram)
        res += '\n\n'
        res += 'Bigram frequencies in plaintext language (normalized):\n'
        lfreq = sorted_by_freq(pt_alphabet, self.lg.frequency)
        n = len(self.msg)
        lbigr = {xy:int(n*fxy) for (xy,fxy) in self.lg.bigram.items()}
        res += bigram_table(lfreq, lbigr)
        return res

    def symbol_frequencies(self):
        n = len(self.msg)
        sfreq = self.msg_freq.most_common()
        ref_freq = sorted_by_1((x,int(n*fx)) for (x, fx) in self.lg.frequency.items())
        tab = {f'Symbol in "{self.lg.lg}"': [x for (x,_) in ref_freq],
               'Expected': [fx for (_,fx) in ref_freq],
               'Ciphertext Symbol': [x for (x,_) in sfreq],
               'Occurrences': [fx for (_,fx) in sfreq]}
        df = pandas.DataFrame(tab, index=list(range(1,26+1)))
        df.index.name = 'Rank'
        df.style.set_caption('Symbol frequency data')
        IPython.display.display(df)

    def language_histogram(self):
        n = len(self.msg)
        ref_freq = sorted_by_1((x,int(n*fx)) for (x, fx) in self.lg.frequency.items())
        xaxis = f'Symbols in "{self.lg.lg}"'
        yaxis = 'Expected Frequency'
        tab = {xaxis: [x for (x, _) in ref_freq], yaxis: [fx for (_, fx) in ref_freq]}
        df = pandas.DataFrame(tab)
        df.plot.bar(x=xaxis, y=yaxis, rot=0)
        # IPython.display.display(df.plot.bar(x=xaxis, y=yaxis, xrot=0))

    def ciphertext_histogram(self):
        sfreq = self.msg_freq.most_common()
        xaxis = 'Ciphertext Symbols'
        yaxis = 'Frequency'
        tab = {xaxis: [x for (x, _) in sfreq], yaxis: [fx for (_, fx) in sfreq]}
        df = pandas.DataFrame(tab)
        df.plot.bar(x=xaxis, y=yaxis, rot=0)

    def language_bigrams(self):
        n = len(self.msg)
        ref_freq = sorted_by_1((x,int(n*fx)) for (x, fx) in self.lg.frequency.items())
        ref_bigr = {xy:int(n*fxy) for (xy, fxy) in self.lg.bigram.items()}
        ranked = [x for (x,_) in ref_freq]
        dat = {x: list(ref_bigr[x,y] for y in ranked) for x in ranked}

        df = pandas.DataFrame(dat, index=ranked)
        df[df.eq(0)] = ''
        IPython.display.display(df)

    def ciphertext_bigrams(self):
        n = len(self.msg)
        sfreq = self.msg_freq.most_common()
        ref_freq = sorted_by_1((x,int(n*fx)) for (x, fx) in self.lg.frequency.items())
        ref_bigr = {xy:int(n*fxy) for (xy, fxy) in self.lg.bigram.items()}
        ranked = [x for (x,_) in sfreq]
        dat = {x: list(self.msg_bigram[x,y] for y in ranked) for x in ranked}
        df = pandas.DataFrame(dat, index=ranked)
        df[df.eq(0)] = ''
        IPython.display.display(df)

    def repeating_patterns(self):
        # TODO FIX THIS
        # Report all patterns of length l and #occurrences > 1"""
        n = len(self.msg)
        dat = dict()
        for l in range(3, n):
            pats = Counter(msg[i:i+l] for i in range(n - (l-1)))
            mp = sorted_by_1((x, nx) for (x, nx) in pats.items() if nx > 1)
            if len(mp) == 0:
                break
            res += f'<div>\n<strong>Patterns of length {l}:</strong>'
            res += '<pre> {} </pre>\n</div>'.format(' '.join(f'{x} {nx}' for (x, nx) in mp))
        return res


class Shell(cmd.Cmd):
    intro = 'Welcome to the substitution solver.  Type help or ? to list commands.\n'
    prompt = '[Command:] '
    file = None

    def __init__(self, solver, browser=''):
        super().__init__()
        self.core = solver
        self.browser = browser

    def do_quit(self, arg):
        """Quit the program."""
        print('Au revoir!')
        return True

    def do_key(self, arg):
        """Show the current (partial) decryption key."""
        if arg:
            if len(arg) == len(pt_alphabet) and all(x == '-' or x in pt_alphabet for x in arg):
                self.core.map_to(ct_alphabet, arg)
            else:
                print(f'Illegal (partial) decryption key "{arg}"')
                return
        print(f'{self.core.key_string()}')

    def do_show(self, arg):
        """Show the ciphertext and decrypt to plaintext
        using the current (partial) key.
        """
        print(self.core.decipher())

    def do_set(self, args):
        """Map ciphertext symbol C to plaintext symbol p: set C p"""
        usage = (f'Usage: set C p\n'
                 f'       where C = ciphertext symbol (from {ct_alphabet})\n'
                 f'       where p = plaintext symbol (from {pt_alphabet}) or -')
        parts = args.split()
        if len(parts) != 2:
            print(usage)
            return
        (c, p) = parts
        if (len(c) != 1 or (c not in ct_alphabet)
            or len(p) != 1 or (p not in pt_alphabet and p != '-')):
            print(usage)
            return
        self.core.set(c, p)

    def do_unset(self, arg):
        """Set ciphertext symbol C to - (unknown): unset C"""
        if len(arg) != 1 or not arg in ct_alphabet:
            print(f'"{arg}" is not a valid ciphertext symbol\nUsage: unset C')
            return
        self.core.unset(arg)

    def do_map(self, arg):
        """map CWORD pword: set each symbol in CWORD to the corresponding symbol in pword."""
        usage = ('Usage: map CWORD pword\n'
                 '      where CWORD and pword have the same length;'
                 f'      CWORD contains only symbols from {ct_alphabet}'
                 f'      pword contains only symbols from {pt_alphabet} or -')
        args = arg.strip().split()
        if len(args) != 2:
            print(usage)
            return
        cword, pword = args
        if len(cword) != len(pword) \
           or not all(c in ct_alphabet for c in cword) \
           or not all((p in pt_alphabet or p == '-') for p in pword):
            print(usage)
            return
        self.core.map_to(cword, pword)

    def do_find_qu(self, arg):
        """Suggest likely "qu" pairs."""
        self.core.find_qu()

    def do_consonants(self, arg):
        """consonants: find probable consonants using Gaines' method."""
        self.core.gaines()

    def do_vowels(self, arg):
        """vowels: find probable vowels using Sukhotin's method."""
        self.core.find_vowels()

#    def do_probable(self, arg):
#        """Give a list of probable ciphertext strings corresponding to the given plaintext."""
#        usage = 'Usage: probable plaintext_word'
#        args = arg.strip().split()
#        if len(args) != 1:
#            print(usage)
#            return
#        word = args[0]
#        if not all(x in pt_alphabet for x in word):
#            print(f'"{word}" is not composed of symbols'
#                  f' from the plaintext argument ({pt_argument})')
#            print(usage)
#            return
#        candidates = self.core.find_probable_word(word)
#        if len(candidates) == 0:
#            print(f'No candidates found')
#            return
#        print(f'Candidates for {word}:')
#        for candidate in candidates:
#            print(f'{" "*15}{candidate}')

