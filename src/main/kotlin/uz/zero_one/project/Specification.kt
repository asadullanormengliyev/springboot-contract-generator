package uz.zero_one.project

import org.springframework.data.jpa.domain.Specification

class OrganisationSpecification {

    companion object {
        fun nameLike(name: String?): Specification<Organisation>? {
            return if (!name.isNullOrBlank()) {
                Specification { root, _, cb ->
                    cb.like(cb.lower(root.get("name")), "%${name.lowercase()}%")
                }
            } else null
        }

        fun addressEqual(address: String?): Specification<Organisation>? {
            return if (!address.isNullOrBlank()) {
                Specification { root, _, cb ->
                    cb.equal(cb.lower(root.get("address")), address.lowercase())
                }
            } else null
        }

        fun notDeleted(): Specification<Organisation> {
            return Specification { root, _, cb ->
                cb.isFalse(root.get("deleted"))
            }
        }
    }
}

class UserSpecification {

    companion object {

        fun statusEquals(status: Status?): Specification<User>? {
            return if (status != null) {
                Specification { root, _, cb ->
                    cb.equal(root.get<Status>("status"), status)
                }
            } else null
        }

        fun roleEquals(role: UserRole?): Specification<User>? {
            return if (role != null) {
                Specification { root, _, cb ->
                    cb.equal(root.get<UserRole>("role"), role)
                }
            } else null
        }

        fun usernameLike(username: String?): Specification<User>? {
            return if (!username.isNullOrBlank()) {
                Specification { root, _, cb ->
                    cb.like(cb.lower(root.get("username")), "%${username.lowercase()}%")
                }
            } else null
        }

        fun fullNameLike(fullName: String?): Specification<User>?{
            return if (!fullName.isNullOrBlank()){
                Specification{root,_,cb ->
                    cb.like(cb.lower(root.get("fullName")), "%${fullName.lowercase()}%")
                }
            }else null
        }

        fun lastNameLike(lastName: String?): Specification<User>?{
            return if (!lastName.isNullOrBlank()){
                Specification{root,_,cb ->
                    cb.like(cb.lower(root.get("fullName")), "%${lastName.lowercase()}%")
                }
            }else null
        }

        fun nameLike(search: String?): Specification<User>? {
            return if (!search.isNullOrBlank()) {
                Specification { root, _, cb ->
                    val fullNamePredicate = cb.like(cb.lower(root.get("fullName")), "%${search.lowercase()}%")
                    val lastNamePredicate = cb.like(cb.lower(root.get("lastName")), "%${search.lowercase()}%")
                    cb.or(fullNamePredicate, lastNamePredicate)
                }
            } else null
        }

        fun fromOrganisationWithAllowedRoles(organisationId: Long?): Specification<User>? {
            return if (organisationId != null) {
                Specification { root, _, cb ->
                    cb.and(
                        cb.equal(root.get<Organisation>("organisation").get<Long>("id"), organisationId),
                        cb.isFalse(root.get("deleted")),
                        root.get<UserRole>("role").`in`(listOf(UserRole.DIRECTOR, UserRole.OPERATOR, UserRole.USER))
                    )
                }
            } else null
        }

        fun isNotDeleted(): Specification<User> {
            return Specification { root, _, cb ->
                cb.equal(root.get<Boolean>("deleted"), false)
            }
        }

    }
}

class TemplateSpecification{
    companion object{

        fun titleSearch(title: String?): Specification<Template>?{
            return if (!title.isNullOrBlank()){
                Specification{root, query, builder ->
                    builder.like(builder.lower(root.get("title")),"%${title.lowercase()}%")
                }
            }else null
        }

        fun notDeleted(): Specification<Template>{
            return Specification{root, query, builder ->
                builder.equal(root.get<Boolean>("deleted"),false)
            }
        }

        fun getAll(user: User): Specification<Template>{
            return Specification{root, query, builder ->
                builder.equal(root.get<Organisation>("organisation"), user.organisation)
            }
        }

    }
}

class ContractSpecification{
    companion object{

        fun notDeleted(): Specification<Contract>{
            return Specification{root, query, builder ->
                builder.equal(root.get<Boolean>("deleted"),false)
            }
        }

        fun templateTitleLike(title: String?): Specification<Contract>? {
            return if (!title.isNullOrBlank()) {
                Specification { root, _, builder ->
                    builder.like(
                        builder.lower(root.get<Template>("template").get("title")),
                        "%${title.lowercase()}%"
                    )
                }
            } else null
        }

        fun byUser(user: User): Specification<Contract> {
            return when (user.role) {
                UserRole.DIRECTOR -> Specification { root, _, cb ->
                    cb.equal(root.get<Organisation>("organisation"), user.organisation)
                }
                UserRole.OPERATOR -> Specification { root, query, cb ->
                    val subquery = query?.subquery(Long::class.java)
                    val assignmentRoot = subquery?.from(ContractAssignment::class.java)
                    subquery?.select(assignmentRoot?.get<Contract>("contract")?.get<Long>("id"))
                        ?.where(cb.equal(assignmentRoot?.get<User>("operator")?.get<Long>("id"), user.id))
                    val assignedContracts = cb.`in`(root.get<Long>("id")).value(subquery)
                    val createdContracts = cb.equal(root.get<User>("operator").get<Long>("id"), user.id)
                    cb.or(assignedContracts, createdContracts)
                }
                else -> Specification { _, _, cb -> cb.disjunction() }
            }
        }

    }
}

class DownloadHistorySpecification{
    companion object{

        fun byUser(userId: Long): Specification<DownloadHistory> {
            return Specification { root, _, cb ->
                cb.equal(root.get<User>("user").get<Long>("id"), userId)
            }
        }

        fun statusEquals(downloadStatus: DownloadStatus?): Specification<DownloadHistory>? {
            return if (downloadStatus != null) {
                Specification { root, _, cb ->
                    cb.equal(root.get<Status>("downloadStatus"), downloadStatus)
                }
            } else null
        }

        fun notDeleted(): Specification<DownloadHistory>{
            return Specification{root, query, builder ->
                builder.equal(root.get<Boolean>("deleted"),false)
            }
        }
    }
}