#!/usr/bin/env python3
"""
Tools for cryptanalyis of Vigenere ciphers
author: Matthieu Lequesne (matthieu.lequesne@inria.fr)
based on scripts by François Morain and Ben Smith
date: 2023/09/14
"""

import random
from collections import Counter
import itertools
import operator
import cmd
import pandas
pandas.set_option('display.max_columns', None)
import matplotlib.pyplot as plt
import IPython.display

pt_alphabet = ''.join([chr(ord('a')+i) for i in range(26)])
ct_alphabet = ''.join([chr(ord('A')+i) for i in range(26)])


def sorted_by_freq(iterable, freq):
    """sorted by frequency in dict/Counter freq (most frequent first)."""
    return sorted(iterable, key=lambda x: -freq[x])

def sorted_by_1(iterable):
    """sorted by their second components in descending order."""
    return sorted(iterable, key=operator.itemgetter(1), reverse=True)

def apply_monospace_font(s):
    return f'font-family: "Courier New", monospace;'

class Language:
    """Data and tools for a given language.

    Data attributes:
        - vowels = ['a', 'e', 'i', 'o', 'u', 'y']
        - frequency = { i: freq(chr(i)) in language }
        - bigram = { (i,j): freq(chr(i)chr(j)) in language }
    """
    def __init__(self, lg):
        if lg not in ['fr', 'en', 'de']:
            print(f'Sorry, unknown language: {lg}')
            return
        self.lg = lg
        self.nb_letters = 26
        self.upper_range = range(65, 91)
        self.lower_range = range(97, 123)
        self.vowels = ['a', 'e', 'i', 'o', 'u', 'y']
        self._freq_filename = f'./Data/{lg}/freq.data'
        self._bigr_filename = f'./Data/{lg}/bigrammes.data'
        self.dico_filename = f'./Data/{lg}/dico_{lg}.data'
        # Load frequencies
        with open(self._freq_filename, 'r') as fd:
            self.frequency = dict((ord(x), float(fx)) for (x,fx) in (s.strip().split() for s in fd))
        # Ensure no bigrams are nonexistent: lets us iterate over bigrams
        self.bigram = dict.fromkeys(itertools.product(pt_alphabet, pt_alphabet), 0)
        self.transition_prob = {}
        with open(self._bigr_filename, 'r') as fd:
            for s in fd:  # s = "a ....."
                t = s.strip().split( )  # t = ['a', '0.00033', ...]
                (x, x_trans) = (t[0], list(zip(pt_alphabet, map(float, t[1:]))))
                x_tot = sum(p for (y, p) in x_trans)
                self.bigram.update(((x,y), fxy) for (y, fxy) in x_trans)
                self.transition_prob.update(((x,y), fxy/x_tot) for (y, fxy) in x_trans)




class Solver:
    def __init__(self, filename, language):
        self.msg = ''
        with open(filename, 'r') as f:
            self.msg = f.read( ).replace('\n', '')
        self.msg_freq = Counter(dict.fromkeys(ct_alphabet, 0))  # Force any absent symbols to 0
        self.msg_freq.update(self.msg)
        self.msg_bigram = Counter(dict.fromkeys(itertools.product(ct_alphabet, ct_alphabet), 0))
        self.msg_bigram.update(zip(self.msg[:-1], self.msg[1:]))
        self.lg = Language(language)
        self.key = []
        self.clear = ['-' for i in range(len(self.msg))]

    def print_key(self):
        """A string representation of the current (partial) decryption key."""
        if self.key==[]:
            print("The key length is not defined yet.")
        else:
            print("Key length = "+str(len(self.key)))
            print("Key = "+str(self.key))
            print("-1 = key value not set")

    def list_kasiski(self):
        L = []
        msg = self.msg
        for i in range(len(msg)):
            for j in range(i+4, len(msg)):
                pat = msg[i:j]
                found = False
                for k in range(j+1, len(msg)-len(pat)):
                    if msg[k:k+j-i] == pat:
                        L.append([pat,i,k,k-i])
                        found = True
                if not found:
                    break
        return sorted(L, key=lambda x: -len(x[0]))

    def kasiski(self):
        print("Kasiski: 20 longest repeated patterns")
        L = self.list_kasiski()
        L = L[:20]
        for i in range(len(L)):
            L[i].append(divisors(L[i][3]))        
        columns = ['pattern', '1st occurence', '2nd occurence', 'distance', 'divisors']
        df = pandas.DataFrame(L, columns=columns)
        IPython.display.display(df)        
        print()

    def friedman(self):
        print("Friedman: value of auto-correlation index for 1 <= k < 50")
        msg = self.msg
        lci = [(i,sum(1 for (x,y) in zip(msg,msg[i:]+msg[:i]) if x == y))
                for i in range(1,50)]
        lci = [(k,index/(len(msg)-k)) for (k,index) in lci]

        xaxis = 'Value of k'
        yaxis = 'Auto-correlation index'
        tab = {xaxis: [x for (x, _) in lci], yaxis: [fx for (_, fx) in lci]}
        df = pandas.DataFrame(tab)
        fig, ax = plt.subplots(figsize=(12, 6))
        df.plot.bar(ax=ax, width=0.5, x=xaxis, y=yaxis, rot=0)
        
    def set_key_length(self, n):
        self.key = [-1]*n
        print("Key length set to "+str(n)+".")
        
    def print_clear(self):
        """Decrypt the ciphertext using the current (partial) key."""
        if self.key==[]:
            print("The key length should be defined to use this tool")
        else:
            print_array(self.clear, len(self.key))

    def shift_letter(self, ch, s):
        newch = ord(ch.lower())+s;
        if not newch in self.lg.lower_range:
            newch -= self.lg.nb_letters;
        return chr(newch)

    def shift_one_column(self, j, s):
        if self.key==[]:
            print("The key length should be defined to use this tool")
            return
        K = len(self.key)
        msg = self.msg
        nrows = len(msg) // K
        if len(self.msg) % K != 0:
            nrows = nrows+1
        # determine real number of rows for column j
        if nrows*K+j >= len(self.msg):
            nrows -= 1
        return [self.shift_letter(msg[i*K+j],s) for i in range(nrows)]
            
    def freq_tab(self, s):
        """frequences for letters in s[]
        OUTPUT: (freq, bigr)
        """
        freq = {i:0 for i in self.lg.lower_range}
        for si in s:
            freq[ord(si)] += 1
        return freq

    def most_frequent(self, sfreq, cols):
        """intersect the letters in cols with the most frequent"""
        f = self.freq_tab(cols)
        sf = sorted(self.lg.lower_range, key=lambda j:-f[j])
        return sum(1 for x in sf[0:10] if x in sfreq)

    def best_shift(self, arg):
        if self.key==[]:
            print("The key length should be defined to use this tool")
            return
        K = len(self.key)
        if not(arg.isdigit()) or int(arg)<0 or int(arg)>=K:
            print(f'"{arg}" is not a valid column index')
            return
        j = int(arg)
        
        lgfreq = self.lg.frequency
        #lgbigr = self.lg.bigram
        trprob = self.lg.transition_prob
        # print(trprob)
        
        mostfreq = sorted_by_freq(self.lg.lower_range, lgfreq)[0:10]
        tab = []
        
        for s in range(self.lg.nb_letters):
            cols = self.shift_one_column(j, s)
            nb = self.most_frequent(mostfreq, cols)
            tr = 0

            # len(cols) is almost always len(msg)//K
            # see right of the column if j+1 was found
            if j < K-1 and self.key[j+1] != -1:
                tr += sum(trprob[(cols[i]), (self.clear[i*K+j+1])]
                          for i in range(len(cols)))
            # see left of the column if j-1 was found
            if j > 0 and self.key[j-1] != -1:
                tr += sum(trprob[(self.clear[i*K+j-1]), (cols[i])]
                        for i in range(len(cols)))
            tab.append([s, nb, int(100*tr)])
        print("[shift, #intersection, trans_proba]")
        print(sorted(tab,key=lambda x:-x[1])[0:5], sep='\n')

    def bruteforce_column(self, arg):
        if self.key==[]:
            print("The key length should be defined to use this tool")
            return
        K = len(self.key)
        if not(isinstance(arg,int)) or arg<0 or arg>=K:
            print(f'"{arg}" is not a valid column index')
            return
        j = int(arg)
        data = []
        for s in range(self.lg.nb_letters):
            cols = self.shift_one_column(j, s)
            data.append([s,''.join(cols)])
        columns = ['shift', 'text']
        df = pandas.DataFrame(data, columns=columns)
        df = df.style.applymap(apply_monospace_font)
        IPython.display.display(df)

    def maximize_frequent_letters(self, arg):
        if self.key==[]:
            print("The key length should be defined to use this tool")
            return
        K = len(self.key)
        if not(isinstance(arg,int)) or arg<0 or arg>=K:
            print(f'"{arg}" is not a valid column index')
            return
        j = int(arg)
        lgfreq = self.lg.frequency
        mostfreq = sorted_by_freq(self.lg.lower_range, lgfreq)[0:10]
        data = []
        for s in range(self.lg.nb_letters):
            cols = self.shift_one_column(j, s)
            nb = self.most_frequent(mostfreq, cols)
            data.append([s,nb,''.join(cols)])
        data = sorted(data, key=lambda x: -x[1])[:10]
        columns = ['shift', 'size of intersection', 'text']
        df = pandas.DataFrame(data, columns=columns)
        df = df.style.applymap(apply_monospace_font)
        print("Top 10 values of shift with highest intersection of frequent letters")
        IPython.display.display(df)
        
    def shift_column(self, j, s):
        K = len(self.key)
        msg = self.msg
        nrows = len(msg) // K
        if len(msg) % K != 0:
            nrows = nrows+1
        for i in range(nrows):
            jj = i*K+j
            if i < nrows-1 or jj < len(msg):
                self.clear[jj] = self.shift_letter(self.msg[jj], s)

    def set_key(self, arg):
        arg = arg.split(' ')
        if len(arg)!=2:
            print("'set' expects two integer arguments.")
            return
        if not(arg[0].isdigit()):
            print(f'"{arg[0]}" is not a valid integer')
            return
        if not(arg[1].isdigit()):
            print(f'"{arg[1]}" is not a valid integer')
            return
        if self.key==[]:
            print("The key length should be defined to use this tool")
            return
        K = len(self.key)
        j = int(arg[0])
        s = int(arg[1])
        if not(0 <= j < K):
            print("The column number should be between 0 and "+str(K-1)+".")
            return
        if not(0 <= s < self.lg.nb_letters):
            print("The shift should be between 0 and "+str(self.lg.nb_letters-1)+".")
        self.key[j] = s
        self.shift_column(j,s)

    def unset_column(self, arg):
        arg = arg.split(' ')
        if len(arg)!=1:
            print("'unset' expects one integer argument.")
            return
        if not(arg[0].isdigit()):
            print(f'"{arg[0]}" is not a valid integer')
            return
        if self.key==[]:
            print("The key length should be defined to use this tool")
            return
        K = len(self.key)
        j = int(arg[0])
        if not(0 <= j < K):
            print("The column number should be between 0 and "+str(K-1)+".")
            return
        self.key[j] = -1
        clear = self.clear
        nrows = len(clear) // K
        if len(clear) % K != 0:
            nrows = nrows+1
        for i in range(nrows):
            jj = i*K+j
            if i < nrows-1 or jj < len(clear):
                self.clear[jj] = '-'

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


                

def print_array(text, K):
    nrows = len(text) // K
    if len(text) % K != 0:
        nrows = nrows+1
    for i in range(nrows):
        print(" ".join(str(x) for x in text[i*K:(i+1)*K]))

def divisors(n):
    return [d for d in range(2, n+1) if n % d == 0]

       

class Shell(cmd.Cmd):
    intro = 'Welcome to the Vigenere cipher solver.  Type help or ? to list commands.\n\n'
    intro += 'List of commands:\n'
    intro += "- 'best j' \tfinds the best shift for column j\n"
    intro += "- 'help' \tprints the help\n"
    intro += "- 'key' \tshows the key\n"
    intro += "- 'length n' \tsets the key length to n\n"
    intro += "- 'quit' \tquits the loop\n"
    intro += "- 'unset j' \tunsets the column j\n"
    intro += "- 'set j s' \tsets the shift of column j to s\n"
    intro += "- 'show' \tshows the deciphered text\n"

    intro += "\nStart by setting the key length using the command 'length'.\n"

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
        self.core.print_key()
        
    def do_length(self, arg):
        """Set the length of the decryption key."""
        if not(arg.isdigit()) or int(arg)==0:
            print(f'"{arg}" is not a valid key length\nUsage: length N (where N is a positive integer)')
            return
        self.core.set_key_length(int(arg))

    def do_show(self, arg):
        """Show the ciphertext and decrypt to plaintext
        using the current (partial) key.
        """
        self.core.print_clear()

    def do_best(self, arg):
        """Find the best shift for a given column. The column number must be between in [0,K-1] where K is the key length."""
        self.core.best_shift(arg)

    def do_set(self, arg):
        """Set one value of the key. \nUsage: if the shift of the j-th column is s, write 'set j s'"""
        self.core.set_key(arg)

    def do_unset(self, arg):
        """Unset the value of the key corresponding to this column. \nUsage: to unset the value of j-th column, write 'unset j'"""
        self.core.unset_column(arg)

