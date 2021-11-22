#include <iostream>

using namespace std;

#ifndef _WINDOWS_H
typedef unsigned char BYTE;
typedef unsigned char BAJT;//8bitu 
typedef bool BIT;
#endif

enum class typ_hodnoty_promene{
cislo_cele,//signed int, 2nebo4bajty(podle potřeby)
cilso_cele_bezznameka,//unsigned int, 2nebo4bajty(podle potřeby)
cislo_cele_dlouhe, //signed long,8bajtu
cislo_cele_dlouhe_bezznameka, //Unsigned long,8bajtu
cislo_cele_kratke, //short, 2bajty
cislo_sn_des_radky,//float, 4bajty
text,//string, 18+(2*poc_znaku)bajtu
znak,//char, 1bajt(hodnoty podle potřeby)
znak_bezznameka,//unsigned char, 1bajt(hodnoty od 0-255)
znak_sznamenkem,//signed char, 1bajt(hodnoty od -127 do 127)
bit, //bit, 1/8bajtu

}

struct typ_promene{
   bool konstanta;//const
   bool radkova;//inline
   bool externi;//extern, pro ostatní moduly programu
   bool staticka;//static
   bool virtualni;//virtual, viz třídy 

   
};

//struktura proměné
struct variable{
   string nazev;
   byte hodnota;
   byte velikost;
   string soubor;//umístění, cesta
   byte adresa;


};
