#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

typedef unsigned char uchar;

static void CodeAux(uchar out[], const int k, const uchar trois[3])
{
    int n = 0, i, j, r;

    /* 3 octets produisent 24 bits */
    for(i = 0; i < 3; i++)
	n = (n << 8) + (int)trois[i];
    /* qui fournissent 4 nombres de 6 bits */
    for(i = 0, j = k+3; i < 4; i++, j--){
	r = n & 63;
	n = n >> 6;
	if(r <= 25)
	    out[j] = 'A'+r;
	else if(r <= 51)
	    out[j] = 'a'+(r-26);
	else if(r <= 61)
	    out[j] = '0'+(r-52);
	else if(r == 62)
	    out[j] = '+';
	else /* r == 63 */
	    out[j] = '/';
    }
}

/* Code le tableau in[] en base 64 : trois caracte`res de in[0..N[ deviennent 
   quatre caracte`res de out[]; si N n'est pas multiple de 3, on
   padde conforme'ment au RFC.

   On suppose que out est de taille >= 4*N/3.
 */
int CodeBase64(uchar out[], const uchar in[], const int N)
{
    uchar trois[3];
    int N64, i, j, k;

    for(i = 0, k = 0; i < (N/3); i++, k += 4){
	trois[0] = in[3*i];
	trois[1] = in[3*i+1];
	trois[2] = in[3*i+2];
	CodeAux(out, k, trois);
    }
    if((N%3) != 0){
	for(i = 0; i < 3; i++)
	    trois[i] = 0;
	for(i = 0, j = 3*(N/3); j < N; i++, j++)
	    trois[i] = in[j];
	CodeAux(out, k, trois);
	i = 3*(N/3)+3-N; /* i = 1 ou 2 */
	if(i == 2){
	    out[k+2] = '=';
	    out[k+3] = '=';
	}
	else
	    out[k+3] = '=';
    }
    /* N64 est le plus petit multiple de 3 >= N */
    if((N%3) == 0) N64 = N;
    else N64 = N + (3 - (N%3));
    N64 = 4 * (N64/3);
    return N64;
}

/* Retourne le nombre de caracte`res cre'es */
static int DecodeAux(uchar *adro, const uchar *adri)
{
    int n = 0, i;
    const uchar *tmp;
    uchar *tmp2;

    /* fabriquons un entier de 24 bits */
    for(tmp = adri, i = 0; i < 4; tmp++, i++){
	n <<= 6;
	if((*tmp >= 'A') && (*tmp <= 'Z'))
	    n += (*tmp - 'A');
	else if((*tmp >= 'a') && (*tmp <= 'z'))
	    n += 26 + (*tmp - 'a');
	else if((*tmp >= '0') && (*tmp <= '9'))
	    n += 52 + (*tmp - '0');
	else if(*tmp == '+')
	    n += 62;
	else if(*tmp == '/')
	    n += 63;
	/* le cas *tmp == '=' n'est pas pris en compte */
    }
    for(tmp2 = adro+2, i = 0; i < 3; tmp2--, i++){
	*tmp2 = (uchar)(n & 255);
	n >>= 8;
    }
    return 1;
}

/* De'code in[0..N64[ en base 64 avec re'sultat dans le tableau out[].
   On suppose que 4 | N64 et out[] est de taille >= 3*N64/4.
   Retourne la vraie longueur.
*/
void DecodeBase64(uchar *out, const uchar *in, const int N64)
{
    int i;
    uchar *adro;
    const uchar *adri;

    assert((N64 & 3) == 0);
    for(adri = in, adro = out, i = 0; i < (N64/4); adri += 4, adro += 3, i++)
	DecodeAux(adro, adri);
}
