# Better Auth Ruby - Makefile
# Este archivo te ayuda a ejecutar comandos comunes de desarrollo
# Cada comando tiene comentarios explicativos para aprender

# Variables de color para hacer la salida más legible
BLUE := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
NC := \033[0m # No Color

# =============================================
# COMANDOS PRINCIPALES DE DESARROLLO
# =============================================

# Instala todas las dependencias del proyecto
# Equivale a: bundle install
.PHONY: install
install:
	@echo "$(BLUE)📦 Instalando dependencias...$(NC)"
	bundle install
	@echo "$(GREEN)✓ Dependencias instaladas$(NC)"

# Configuración inicial del proyecto (primer clone)
# Ejecuta bin/setup que hace bundle install
.PHONY: setup
setup:
	@echo "$(BLUE)🔧 Configurando proyecto...$(NC)"
	bin/setup
	@echo "$(GREEN)✓ Proyecto configurado$(NC)"

# =============================================
# COMANDOS DE CALIDAD DE CÓDIGO
# =============================================

# Revisa que el código cumpla con el estilo StandardRB
# Muestra errores pero NO los corrige automáticamente
.PHONY: lint
lint:
	@echo "$(BLUE)🔍 Revisando estilo de código...$(NC)"
	bundle exec standardrb
	@echo "$(GREEN)✓ Código cumple con el estilo$(NC)"

# Revisa Y AUTOCORRIGE problemas de estilo con StandardRB
# Úsalo cuando quieras formatear todo automáticamente
.PHONY: lint-fix
lint-fix:
	@echo "$(BLUE)🔧 Corrigiendo estilo de código automáticamente...$(NC)"
	bundle exec standardrb --fix
	@echo "$(GREEN)✓ Código corregido$(NC)"

# =============================================
# COMANDOS DE TESTING
# =============================================

# Ejecuta TODOS los tests (core + rails adapter)
# Es lo mismo que: bundle exec rake ci
.PHONY: test
test:
	@echo "$(BLUE)🧪 Ejecutando todos los tests...$(NC)"
	bundle exec rake test
	@echo "$(GREEN)✓ Tests completados$(NC)"

# Ejecuta solo los tests del core (Minitest)
# Son los tests en el directorio test/
.PHONY: test-core
test-core:
	@echo "$(BLUE)🧪 Ejecutando tests del core...$(NC)"
	bundle exec rake test:core
	@echo "$(GREEN)✓ Tests del core completados$(NC)"

# Ejecuta solo los tests del adapter Rails (RSpec)
# Son los tests en el directorio spec/
.PHONY: test-rails
test-rails:
	@echo "$(BLUE)🧪 Ejecutando tests del adapter Rails...$(NC)"
	bundle exec rspec
	@echo "$(GREEN)✓ Tests de Rails completados$(NC)"

# Ejecuta tests con cobertura de código
# Genera reporte en coverage/index.html
.PHONY: test-coverage
test-coverage:
	@echo "$(BLUE)📊 Ejecutando tests con cobertura...$(NC)"
	COVERAGE=true bundle exec rake test
	@echo "$(GREEN)✓ Reporte de cobertura en coverage/index.html$(NC)"

# =============================================
# COMANDOS DE INTEGRACIÓN CONTINUA (CI)
# =============================================

# Ejecuta TODO el pipeline de CI localmente
# 1. Lint (StandardRB)
# 2. Tests (Minitest + RSpec)
# Esto es lo que corre GitHub Actions en cada PR
.PHONY: ci
ci:
	@echo "$(BLUE)🔧 Ejecutando CI completo...$(NC)"
	bundle exec rake ci
	@echo "$(GREEN)✓ CI completado exitosamente$(NC)"

# =============================================
# COMANDOS DE DESARROLLO INTERACTIVO
# =============================================

# Abre una consola interactiva (IRB) con la gema cargada
# Útil para probar código manualmente
.PHONY: console
console:
	@echo "$(BLUE)💻 Abriendo consola interactiva...$(NC)"
	bin/console

# =============================================
# COMANDOS DE PUBLICACIÓN (RELEASE)
# =============================================

# PASO 1: Actualiza la versión en version.rb
# Debes hacerlo manualmente antes de release

# PASO 2: Crea un git tag con la versión
# Ejemplo: make tag VERSION=0.1.0
.PHONY: tag
tag:
ifndef VERSION
	$(error VERSION no está definido. Usa: make tag VERSION=0.1.0)
endif
	@echo "$(YELLOW)🏷️  Creando tag v$(VERSION)...$(NC)"
	git add -A
	git commit -m "chore: release v$(VERSION)"
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	@echo "$(GREEN)✓ Tag creado. Ahora haz: git push origin main --tags$(NC)"

# PASO 3 (MANUAL): Publica la gema a RubyGems manualmente
# Solo úsalo si NO estás usando GitHub Actions
.PHONY: release-manual
release-manual:
	@echo "$(YELLOW)📦 Construyendo gema...$(NC)"
	gem build better_auth.gemspec
	@echo "$(YELLOW)🚀 Publicando a RubyGems...$(NC)"
	gem push better_auth-*.gem
	@echo "$(GREEN)✓ Gema publicada$(NC)"

# =============================================
# COMANDOS DE BASES DE DATOS (TESTING)
# =============================================

# Inicia los contenedores de Docker para testing
# (PostgreSQL, MySQL, Redis)
.PHONY: db-up
db-up:
	@echo "$(BLUE)🐳 Iniciando bases de datos...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✓ Bases de datos listas$(NC)"

# Detiene los contenedores de Docker
.PHONY: db-down
db-down:
	@echo "$(BLUE)🐳 Deteniendo bases de datos...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Bases de datos detenidas$(NC)"

# =============================================
# COMANDOS DE LIMPIEZA
# =============================================

# Limpia archivos temporales y la gema compilada
.PHONY: clean
clean:
	@echo "$(BLUE)🧹 Limpiando archivos temporales...$(NC)"
	rm -rf *.gem coverage/ .bundle/
	@echo "$(GREEN)✓ Limpieza completada$(NC)"

# =============================================
# AYUDA
# =============================================

# Muestra todos los comandos disponibles con descripción
.PHONY: help
help:
	@echo "$(GREEN)Better Auth Ruby - Comandos disponibles:$(NC)"
	@echo ""
	@echo "$(YELLOW)Instalación:$(NC)"
	@echo "  make install       - Instala dependencias (bundle install)"
	@echo "  make setup         - Configuración inicial del proyecto"
	@echo ""
	@echo "$(YELLOW)Desarrollo:$(NC)"
	@echo "  make console       - Abre consola interactiva (IRB)"
	@echo "  make lint          - Revisa estilo de código"
	@echo "  make lint-fix      - Corrige estilo automáticamente"
	@echo ""
	@echo "$(YELLOW)Testing:$(NC)"
	@echo "  make test          - Ejecuta todos los tests"
	@echo "  make test-core     - Solo tests del core (Minitest)"
	@echo "  make test-rails    - Solo tests Rails (RSpec)"
	@echo "  make test-coverage - Tests con reporte de cobertura"
	@echo "  make ci            - Ejecuta CI completo (lint + test)"
	@echo ""
	@echo "$(YELLOW)Bases de datos (Docker):$(NC)"
	@echo "  make db-up         - Inicia PostgreSQL, MySQL, Redis"
	@echo "  make db-down       - Detiene contenedores"
	@echo ""
	@echo "$(YELLOW)Release:$(NC)"
	@echo "  make tag VERSION=x.x.x  - Crea git tag para release"
	@echo "  make release-manual     - Publica manualmente (NO usar con CI)"
	@echo ""
	@echo "$(YELLOW)Utilidades:$(NC)"
	@echo "  make clean         - Limpia archivos temporales"
	@echo "  make help          - Muestra esta ayuda"
