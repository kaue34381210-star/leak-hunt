"""Tipos compartilhados pelas regras de detecção."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
import re


Validador = Callable[[re.Match[str], str], bool]
ValidadorArquivo = Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class Deteccao:
    """Correspondência encontrada por uma regra."""

    codigo: str
    tipo: str
    valor: str
    inicio: int
    fim: int
    minimo_por_arquivo: int = 1


@dataclass(frozen=True, slots=True)
class Regra:
    """Regra baseada em expressão regular e validação opcional."""

    codigo: str
    tipo: str
    padrao: re.Pattern[str]
    validador: Validador | None = None
    validador_arquivo: ValidadorArquivo | None = None
    grupo_valor: int | str = 0
    minimo_por_arquivo: int = 1
    valores_permitidos: frozenset[str] = frozenset()

    def procurar(
        self,
        texto: str,
        arquivo: str | None = None,
    ) -> Iterator[Deteccao]:
        """Produz as correspondências válidas encontradas no texto."""
        if self.validador_arquivo and (
            arquivo is None or not self.validador_arquivo(arquivo)
        ):
            return
        for correspondencia in self.padrao.finditer(texto):
            if self.validador and not self.validador(correspondencia, texto):
                continue
            valor = correspondencia.group(self.grupo_valor)
            if valor in self.valores_permitidos:
                continue
            yield Deteccao(
                codigo=self.codigo,
                tipo=self.tipo,
                valor=valor,
                inicio=correspondencia.start(self.grupo_valor),
                fim=correspondencia.end(self.grupo_valor),
                minimo_por_arquivo=self.minimo_por_arquivo,
            )
