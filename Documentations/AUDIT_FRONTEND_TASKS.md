# Audit Frontend Web — Rapport final

## ✅ Toutes les tâches corrigées

| # | Tâche | Priorité | Statut |
|---|-------|----------|--------|
| 1.1 | Section HTML dupliquée supprimée | 🔴 Critique | ✅ |
| 1.2 | Fonctions JS dupliquées supprimées (4 paires) | 🔴 Critique | ✅ |
| 1.3 | Event listeners AES manquants ajoutés | 🔴 Critique | ✅ |
| 1.4 | Initialisation ProtocolEngine dupliquée corrigée | 🔴 Critique | ✅ |
| 2.1 | Vite ajouté (build tooling + scripts npm) | 🟡 Haute | ✅ |
| 2.2 | Module `env` — shim + alias Vite | 🟡 Haute | ✅ |
| 2.3 | `.gitignore` fixé (fini le `*` agressif) | 🟡 Haute | ✅ |
| 3.2 | CSS extrait dans `styles.css` | 🟢 Moyenne | ✅ |
| 4 | Section Performance simplifiée (stubs retirés) | 🟢 Moyenne | ✅ |
| 5.1 | Champs sensibles en `type="password"` + toggle 👁 | 🔵 Basse | ✅ |
| 5.2 | Content Security Policy ajoutée | 🔵 Basse | ✅ |
| 3.3 | Tests frontend Vitest (10 tests passent) | 🔵 Basse | ✅ |
| 7 | CI/CD — jobs web-frontend + deploy-pages | 🟡 Haute | ✅ |
| 3.1 | TypeScript (optionnel) | 🔵 Basse | ⏭ Reporté |

## Bugs de logique corrigés (cette session)

| # | Bug | Correction |
|---|-----|-----------|
| L1 | `sendMessage` ignorait le retour chiffré | Ajout de l'hex chiffré dans le message : `"Sent: hello \| enc: a1b2..."` |
| L2 | `setInterval(updateStatus, 1000)` en conflit avec `getProtocolState()` | Polling supprimé ; `updateStatus()` appelé explicitement après chaque action + après `initialize()` |
| L3 | `showError()` empilait les erreurs en ordre inverse | Changé `insertBefore(firstChild)` → insertion après `#loading` pour ordre chronologique |
| L4 | `checkMessages()` muet quand `[]` (WASM retourne toujours vide) | Ajout d'un message `'No pending messages (demo limitation)'` |
| L5 | Chiffrement échoué → ancien ciphertext stagnant | `aes-ciphertext` vidé sur erreur |
| L6 | Pas de validation hex sur HMAC & AES inputs | Ajout de `isValidHex()` + messages d'erreur explicites |
| L7 | `getProtocolState()` écrasait le className du status | `className` mis à jour avant `innerHTML` pour garder le style |
| L8 | `initialize()` n'affichait pas le state initial | `updateStatus()` appelé après setup |

## Métriques finales

| Métrique | Avant | Après |
|----------|-------|-------|
| Taille `index.html` | 735 lignes | ~508 lignes (-31%) |
| Build | Aucun | Vite (6 modules, 135ms) |
| CSS | Inline dans HTML | `styles.css` séparé |
| Tests | 0 | 10 (Vitest) |
| CI | Rust uniquement | Rust + Web + Deploy |
| Déploiement | Aucun | GitHub Pages ready |
| Champs sensibles | Texte clair | Password + toggle |
| Polling inutile | setInterval 1s | Supprimé |
| Validation inputs | Aucune | hex validation + messages propres |

## Lancer le frontend

```bash
cd web
npm run dev      # dev server
npm run build    # production build
npm test         # tests (10 tests)
npm run preview  # preview build
```

## À savoir

- Déploiement GitHub Pages : Settings > Pages > Source: **GitHub Actions**
- Rebuild WASM : `npm run build:wasm` (nécessite Rust + wasm-pack)
