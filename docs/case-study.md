# Case study — PhishGuard AI

**Problème.** Les détecteurs de phishing purement basés sur l'IA sont des boîtes noires : un score sans justification n'aide ni l'utilisateur à se protéger, ni l'analyste à trier. J'ai voulu construire un détecteur où chaque point du score est explicable et vérifiable.

**Architecture.** Architecture hexagonale (ports/adapters) en Python/FastAPI : un domaine pur contenant 10 règles déterministes (typosquatting par distance de Levenshtein, mismatch domaine affiché/réel, urgence linguistique, Reply-To divergent, etc.), chacune étant une fonction pure testée avec cas positif et négatif. Une couche LLM optionnelle (Gemini API Free Tier — gratuite) valide les signaux et rédige l'explication, mais son ajustement est **borné à ±15 points** : l'IA enrichit le verdict, elle ne le décide jamais seule. Un provider local (`LocalRulesProvider`), toujours disponible et gratuit, sert de socle : si Gemini échoue (quota gratuit atteint, panne réseau, réponse malformée), l'analyse retombe automatiquement dessus — le projet ne dépend jamais uniquement d'une API externe.

**Livrables.** API FastAPI documentée, dashboard React avec une « barre de traçabilité » (chaque segment du score = une règle et sa preuve), extension Chrome MV3 qui analyse l'email ouvert dans Gmail/Outlook, mode batch (API + CLI) avec rapport agrégé, exports d'incident en Markdown et PDF, le tout conteneurisé avec docker-compose.

**Résultats mesurés.** 31 tests automatisés ; précision 1.00 / rappel 1.00 sur un dataset synthétique de 120 emails (60/60) utilisé comme garde-fou de non-régression — j'assume que ces métriques reflètent l'alignement dataset/règles et je documente les limites attendues en conditions réelles. Un faux positif réel (marque multi-TLD : `amazon.ca` vs `amazon.com`) a été détecté pendant les tests d'intégration, corrigé, et verrouillé par un test de régression.

**Ce que ça démontre.** Conception d'architecture testable, intégration LLM responsable (bornée, avec fallback), rigueur d'évaluation (précision/rappel comme tests), et cadrage éthique d'un projet de cybersécurité défensive.
