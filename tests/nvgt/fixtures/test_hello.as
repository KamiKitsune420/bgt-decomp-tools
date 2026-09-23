// Smoke test: globals, class, function, control flow
int score = 0;
string name = "player";

class Weapon {
    int damage;
    string wname;
    Weapon(int d, string n) { damage = d; wname = n; }
    int get_damage() const { return damage; }
}

void attack(Weapon @w, int times) {
    for (int i = 0; i < times; i++) {
        score += w.get_damage();
        if (score > 100) { print("overkill!"); break; }
        else { print("hit " + i); }
    }
}

void main() {
    Weapon sword(25, "sword");
    attack(sword, 5);
    print(name + " scored " + score);
}
