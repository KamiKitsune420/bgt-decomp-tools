string make(int a) {
    return "n=" + a;
}
void main() {
    string s = make(7);
    print(s.substr(1, 2));
}
