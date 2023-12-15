#ifndef __FRS__BASE64

typedef unsigned char uchar;

/* From the RFC 1421:
   Value Encoding  Value Encoding  Value Encoding  Value Encoding
       0 A            17 R            34 i            51 z
       1 B            18 S            35 j            52 0
       2 C            19 T            36 k            53 1
       3 D            20 U            37 l            54 2
       4 E            21 V            38 m            55 3
       5 F            22 W            39 n            56 4
       6 G            23 X            40 o            57 5
       7 H            24 Y            41 p            58 6
       8 I            25 Z            42 q            59 7
       9 J            26 a            43 r            60 8
      10 K            27 b            44 s            61 9
      11 L            28 c            45 t            62 +
      12 M            29 d            46 u            63 /
      13 N            30 e            47 v
      14 O            31 f            48 w         (pad) =
      15 P            32 g            49 x
      16 Q            33 h            50 y

                  Printable Encoding Characters
*/

/* Code le tableau in[] en base 64 : trois caracte`res de in[0..N[ deviennent 
   quatre caracte`res de out[]; si N n'est pas multiple de 3, on
   padde conforme'ment au RFC.

   On suppose que out est de taille >= 4*N/3.
 */
extern int CodeBase64(uchar *out, const uchar *in, const int N);
/* De'code in[0..N64[ en base 64 avec re'sultat dans le tableau out[].
   On suppose que 4 | N64 et out[] est de taille >= 3*N64/4.
   Retourne la vraie longueur.
*/
extern void DecodeBase64(uchar *out, const uchar *in, const int N64);

#define __FRS__BASE64
#endif
