import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

CLIENT_SECRET = os.environ.get("IR_CLIENT_SECRET", "")

def main():
    print("\n" + "="*50)
    print("🕵️ SKANER POPRAWNOŚCI SEKRETU")
    print("="*50)
    
    length = len(CLIENT_SECRET)
    print(f"📉 Długość w GitHub: {length} znaków")
    print(f"📧 Ty posiadasz:    43 znaki")
    
    if length == 0:
        print("❌ Sekret jest PUSTY! Wklej go ponownie w Secrets.")
        sys.exit(1)

    print("\n🔍 PUNKTY KONTROLNE (Porównaj ze swoim mailem):")
    print("(Liczymy znaki od 1, tak jak ludzie)")
    print("-" * 40)
    
    # Sprawdzamy co 10. znak
    try:
        if length >= 1:
            print(f"1.  Znak PIERWSZY:  '{CLIENT_SECRET[0]}'")
        
        if length >= 10:
            print(f"10. Znak dziesiąty: '{CLIENT_SECRET[9]}'")
            
        if length >= 20:
            print(f"20. Znak dwudziesty:'{CLIENT_SECRET[19]}'")
            
        if length >= 30:
            print(f"30. Znak trzydziesty:'{CLIENT_SECRET[29]}'")
            
        if length >= 40:
            print(f"40. Znak czterdziesty:'{CLIENT_SECRET[39]}'")
            
        if length >= 1:
            print(f"🔚 Znak OSTATNI:    '{CLIENT_SECRET[-1]}'")
            
    except IndexError:
        pass
    
    print("-" * 40)
    print("👉 INSTRUKCJA:")
    print("Spójrz na swój sekret w notatniku/mailu.")
    print("1. Czy Twój 10. znak to to samo co wyżej?")
    print("2. Czy Twój 20. znak to to samo?")
    print("3. Jeśli np. w logu 20. znak to 'X', a u Ciebie 'Y',")
    print("   to znaczy, że błąd jest POMIĘDZY 10 a 20 znakiem.")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()
