// Realistic NVGT test: timers, UI, string ops
string player_name = "hero";
int hp = 100;

class Enemy {
    string name;
    int health;
    Enemy(string n, int h) { name = n; health = h; }
    void hit(int dmg) { health -= dmg; }
    bool alive() const { return health > 0; }
}

void main() {
    Enemy goblin("goblin", 30);
    int rounds = 0;
    while (goblin.alive() && rounds < 10) {
        goblin.hit(7);
        rounds++;
    }
    if (!goblin.alive()) { print(player_name + " wins in " + rounds + " rounds"); }
    else { print("the goblin survived!"); }
}
