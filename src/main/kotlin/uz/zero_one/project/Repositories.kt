package uz.zero_one.project

import jakarta.persistence.EntityManager
import jakarta.transaction.Transactional
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.domain.Specification
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.jpa.repository.support.JpaEntityInformation
import org.springframework.data.jpa.repository.support.SimpleJpaRepository
import org.springframework.data.repository.NoRepositoryBean
import org.springframework.data.repository.findByIdOrNull
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Repository

@NoRepositoryBean
interface BaseRepository<T : BaseEntity> : JpaRepository<T, Long>, JpaSpecificationExecutor<T> {
    fun findByIdAndDeletedFalse(id: Long): T?
    fun trash(id: Long): T?
    fun trashList(ids: List<Long>): List<T>
    fun findAllNotDeleted(): List<T>
    fun findAllNotDeleted(pageable: Pageable): Page<T>
}

class BaseRepositoryImpl<T : BaseEntity>(
    entityInformation: JpaEntityInformation<T, Long>,
    entityManager: EntityManager
) : SimpleJpaRepository<T, Long>(entityInformation, entityManager), BaseRepository<T> {

    val isNotDeletedSpecification = Specification<T> { root, _, cb ->
        cb.equal(root.get<Boolean>("deleted"), false)
    }

    override fun findByIdAndDeletedFalse(id: Long): T? =
        findByIdOrNull(id)?.run { if (deleted) null else this }

    @Transactional
    override fun trash(id: Long): T? = findByIdOrNull(id)?.run {
        deleted = true
        save(this)
    }

    override fun findAllNotDeleted(): List<T> = findAll(isNotDeletedSpecification)

    override fun findAllNotDeleted(pageable: Pageable): Page<T> =
        findAll(isNotDeletedSpecification, pageable)

    @Transactional
    override fun trashList(ids: List<Long>): List<T> = ids.map { trash(it)!! }
}

@Repository
interface UserRepository : BaseRepository<User> {
    fun findByUsername(username: String): User?
    fun existsByUsername(username: String): Boolean
    fun findByUsernameAndDeletedFalse(username: String): User?

    @Query("SELECT u FROM User u WHERE u.deleted = false AND u.role = 'DIRECTOR'")
    fun findAllDirectors(pageable: Pageable): Page<User>

    @Query("select u from User u where u.deleted = false and u.role = 'OPERATOR'")
    fun findAllOperators(pageable: Pageable): Page<User>

    @Query("select u from User u inner join Organisation o on o.id = u.organisation.id where o.id =:organisationId and o.deleted = false and u.deleted = false")
    fun getAllUsersByOrganisation(@Param("organisationId") organisationId: Long): List<User>

    @Query("select u from User u inner join Organisation o on o.id = u.organisation.id where o.id =:organisationId and u.deleted = false and u.role = 'DIRECTOR'")
    fun getAllDirectorsByOrganisationId(@Param("organisationId") organisationId: Long): List<User>

    @Query("SELECT u.organisation FROM User u WHERE u.id = :userId")
    fun findOrganisationByUserId(@Param("userId") userId: Long): Organisation?

    /*@Query("select u from User u where u.organisation.id =:organisationId and u.organisation.deleted = false and u.deleted = false and u.role = 'OPERATOR' and (lower(u.fullName) like lower(concat('%', :search, '%')) or lower(u.lastName) like lower(concat('%', :search, '%')))")
    fun getAllOperatorsByOrganisation(@Param("organisationId") organisationId: Long,pageable: Pageable,
                                      @Param("search") search: String?): Page<User>*/

    @Query("""
    select u from User u 
    where u.organisation.id = :organisationId 
      and u.organisation.deleted = false 
      and u.deleted = false 
      and u.role = 'OPERATOR'
""")
    fun getAllOperatorsByOrganisationSimple(
        @Param("organisationId") organisationId: Long,
        pageable: Pageable
    ): Page<User>

    @Query("""
    select u from User u 
    where u.organisation.id = :organisationId 
      and u.organisation.deleted = false 
      and u.deleted = false 
      and u.role = 'OPERATOR'
      and (
        lower(cast(u.fullName as string)) like lower(concat('%', :search, '%')) 
        or lower(cast(u.lastName as string)) like lower(concat('%', :search, '%'))
      )
""")
    fun getAllOperatorsByOrganisationWithSearch(
        @Param("organisationId") organisationId: Long,
        @Param("search") search: String,
        pageable: Pageable
    ): Page<User>


    fun existsByUsernameAndDeletedFalse(username: String): Boolean
}

@Repository
interface OrganisationRepository : BaseRepository<Organisation> {
    fun existsByNameAndDeletedFalse(name: String): Boolean

    @Query("select o from Organisation o where o.address = :address and o.deleted = false")
    fun searchOrganisationByAddress(@Param("address") address: String): List<Organisation>

    @Query("select o from Organisation o where lower(o.name) like lower(concat('%', :name, '%')) and o.deleted = false")
    fun searchByNameLike(@Param("name") name: String): List<Organisation>

    @Query("select count(o) > 0 from Organisation o where o.id = :id and o.deleted = false")
    fun organisationIdAndDeletedFalse(@Param("id") id: Long): Boolean

}

@Repository
interface TemplateRepository : BaseRepository<Template> {

}

@Repository
interface ContractRepository : BaseRepository<Contract> {
    @Query(
        """
        SELECT c FROM Contract c
        LEFT JOIN FETCH c.values v
        WHERE c.id = :id
    """
    )
    fun findByIdWithValues(@Param("id") id: Long): Contract?

    @Query("select c from Contract c where c.organisation.id =:organisationId and c.organisation.deleted = false and c.deleted = false and (:title IS NULL OR :title = '' OR LOWER(c.template.title) LIKE LOWER(CONCAT('%', :title, '%')))")
    fun getAllContractsByOrganisation(@Param("organisationId") organisationId: Long,
                                       @Param("title") title: String?,
                                       pageable: Pageable): Page<Contract>
}

@Repository
interface TemplateKeyRepository : BaseRepository<TemplateKey> {

    @Query("""SELECT tk FROM TemplateKey tk WHERE tk.template.id = :templateId and tk.template.deleted=false and tk.deleted=false""")
    fun findAllByTemplateId(@Param("templateId") templateId: Long): List<TemplateKey>

    @Modifying
    @Query("UPDATE TemplateKey tk SET tk.deleted = true WHERE tk.template.id = :templateId")
    fun softDeleteAllByTemplateId(@Param("templateId") templateId: Long)

    @Query("select tk.template from TemplateKey tk where tk.id =:templateKey and tk.deleted = false and tk.template.deleted = false")
    fun findTemplateKeyByTemplateId(@Param("templateKey") templateKey: Long): Template?

}

@Repository
interface ContractValueRepository : BaseRepository<ContractValue> {
    fun findByContractIdAndTemplateKeyId(contractId: Long, templateKeyId: Long): ContractValue?

    fun findAllByContractId(contractId: Long): List<ContractValue>

    @Query("select cv from ContractValue cv where cv.contract.id =:contractId and cv.contract.deleted = false")
    fun findAllByContractIds(@Param("contractId") contractId: Long): List<ContractValue>
}

@Repository
interface ContractAssignmentRepository : BaseRepository<ContractAssignment> {
    fun findByContractIdAndOperatorId(contractId: Long, operatorId: Long): ContractAssignment?
    fun findAllByContractId(contractId: Long): List<ContractAssignment>

    @Query("select ca.operator from ContractAssignment ca where ca.contract.id =:contractId and ca.deleted = false and ca.contract.deleted = false")
    fun getAllContractAssignmentByOperator(contractId: Long): List<User>

    @Query("""
    select ca from ContractAssignment ca 
    where ca.contract.id = :contractId 
      and ca.deleted = false 
      and ca.contract.deleted = false 
""")
    fun findAllByContractIdWithOperator(@Param("contractId") contractId: Long): List<ContractAssignment>

    @Query("select ca from ContractAssignment ca where ca.operator.id =:userId and ca.deleted = false and ca.contract.deleted = false ")
    fun findAllByContractByOperator(@Param("userId") userId: Long): List<ContractAssignment>

}

@Repository
interface DownloadHistoryRepository : BaseRepository<DownloadHistory> {
    fun findAllByUser(user: User): List<DownloadHistory>
    fun findAllByUserAndDeletedFalse(user: User, pageable: Pageable): Page<DownloadHistory>
}

@Repository
interface TemplateAssignmentRepository : BaseRepository<TemplateAssignment> {
    fun findByTemplateIdAndOperatorId(templateId: Long, operatorId: Long): TemplateAssignment?

    fun findAllByTemplateId(templateId: Long) : List<TemplateAssignment>

    @Query("select ta from TemplateAssignment ta where ta.template.id =:templateId and ta.deleted = false and ta.template.deleted = false")
    fun findAllByTemplateIdWithOperator(@Param("templateId") templateId: Long): List<TemplateAssignment>

    @Query("select ta from TemplateAssignment ta where ta.operator.id =:userId and ta.deleted = false and ta.template.deleted = false ")
    fun findAllByTemplateByOperator(@Param("userId") userId: Long): List<TemplateAssignment>

    @Query("""
    SELECT ta.template 
    FROM TemplateAssignment ta 
    WHERE ta.operator.id = :operatorId
      AND (:search IS NULL OR :search = '' OR LOWER(ta.template.title) LIKE LOWER(CONCAT('%', :search, '%')))
""")
    fun searchTemplatesByOperatorIdAndTitle(
        @Param("operatorId") operatorId: Long,
        @Param("search") search: String?,
        pageable: Pageable
    ): Page<Template>

}